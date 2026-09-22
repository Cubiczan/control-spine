//! Pure commission engine: deterministic computation from plan config and
//! typed transactions. No clock, filesystem, network, or unseeded randomness
//! — time and data are caller inputs; money is integer cents; all arithmetic
//! is integer and overflow-checked.
//!
//! Output is order-independent: transactions are processed in a canonical
//! order, credit collisions resolve by explicit priority, split rounding
//! uses the largest-remainder rule with content-based tie-breaks, and all
//! output collections are sorted. Reordering the input file cannot change
//! a number.

use std::collections::BTreeMap;

use spine::Finding;

use crate::config::{BandMode, PlanConfig, PlanVersion, ATTAINMENT_SCALE, BASIS_POINTS};
use crate::input::{Credit, Transaction, TransactionsFile, TxnKind};

/// One credited (or clawed-back) share of a transaction.
/// Clawback reversals carry negative amounts and link to the original;
/// the original's lines are never mutated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CreditLine {
    pub transaction_id: String,
    /// Present on clawback reversals only: the original sale's transaction id.
    pub links_original: Option<String>,
    pub rep_id: String,
    pub role: String,
    pub credited_cents: i128,
}

/// One band's contribution to a rep's commission on net credited revenue.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BandSlice {
    pub band_index: usize,
    /// Exclusive upper attainment bound of the band (None = open).
    pub up_to_ppm: Option<u64>,
    pub rate_bps: u32,
    pub slice_cents: i128,
    pub commission_cents: i128,
}

/// Per-rep, per-plan-version commission roll-up. A rep active across a
/// mid-period plan change gets one summary per version — attainment and
/// quota are always measured against the version in force.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RepSummary {
    pub rep_id: String,
    pub plan_version: u32,
    pub band_mode: BandMode,
    pub gross_credited_cents: i128,
    pub returned_cents: i128,
    pub net_credited_cents: i128,
    pub attainment_ppm: i128,
    pub windfall_cap_ppm: Option<u64>,
    pub windfall_cap_applied: bool,
    /// Band slices behind `net_commission_cents` (capped basis applies).
    pub net_band_slices: Vec<BandSlice>,
    pub gross_commission_cents: i128,
    pub net_commission_cents: i128,
    /// `gross_commission − net_commission`: the exact commission reversal
    /// attributable to returns. Under a binding windfall cap this can be
    /// zero — the cap absorbed the return (documented in the README).
    pub clawback_commission_cents: i128,
}

/// Full result of a deterministic commission run.
///
/// `Finding` is a foreign spine type without `PartialEq`, so this struct
/// derives only `Debug` and `Clone` — compare field-wise (tests do).
pub struct EngineOutput {
    pub credit_lines: Vec<CreditLine>,
    pub rep_summaries: Vec<RepSummary>,
    pub findings: Vec<Finding>,
}

/// Engine-level refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    #[error("arithmetic overflow while computing {what}")]
    ArithmeticOverflow { what: &'static str },
    #[error("role {role:?} has no split weight in plan version {version}")]
    MissingRoleWeight { role: String, version: u32 },
}

struct RepAcc {
    gross: i128,
    returned: i128,
}

/// Pass-1 bookkeeping: per transaction id, the winning priority and the
/// winning (rep, role) credits that returns will mirror.
type ResolvedWinners<'k> = BTreeMap<&'k str, (usize, Vec<(String, String)>)>;

/// Run the engine. Pure: same inputs always produce the same output, for
/// any input ordering.
pub fn run(plan: &PlanConfig, txns: &TransactionsFile) -> Result<EngineOutput, EngineError> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut lines: Vec<CreditLine> = Vec::new();
    let mut acc: BTreeMap<(String, usize), RepAcc> = BTreeMap::new();

    // Canonical processing order: by (date, id). Nothing downstream may
    // depend on input order.
    let mut ordered: Vec<&Transaction> = txns.transactions.iter().collect();
    ordered.sort_by(|a, b| (&a.date, &a.transaction_id).cmp(&(&b.date, &b.transaction_id)));

    // Pass 1 — sales: plan-version assignment, collision resolution, splits.
    // Resolved winners feed pass 2: a return mirrors the original's winning
    // credits, which is the clawback linkage.
    let mut resolved: ResolvedWinners<'_> = BTreeMap::new();
    for t in ordered.iter().copied().filter(|t| t.kind == TxnKind::Sale) {
        let Some(vi) = plan.version_index_for_date(t.date) else {
            findings.push(Finding::breach(
                "TXN-UNASSIGNED",
                format!("txn:{}", t.transaction_id),
                format!(
                    "transaction date {txn_date} falls in no plan version effective range; \
                     excluded from crediting",
                    txn_date = t.date
                ),
            ));
            continue;
        };
        let version = &plan.versions[vi];
        let winners = resolve_credit_winners(t, &mut findings);
        if !winners.is_empty() {
            let shares = split_by_role_weights(version, &winners, t.amount_cents)?;
            for ((rep, role), share) in winners.iter().zip(&shares) {
                lines.push(CreditLine {
                    transaction_id: t.transaction_id.clone(),
                    links_original: None,
                    rep_id: rep.clone(),
                    role: role.clone(),
                    credited_cents: *share,
                });
                acc.entry((rep.clone(), vi))
                    .or_insert(RepAcc {
                        gross: 0,
                        returned: 0,
                    })
                    .gross += share;
            }
        }
        resolved.insert(t.transaction_id.as_str(), (vi, winners));
    }

    // Pass 2 — returns: clawback reversals in the ORIGINAL's plan version.
    for t in ordered
        .iter()
        .copied()
        .filter(|t| t.kind == TxnKind::Return)
    {
        let original_id = match t.original_transaction_id.as_deref() {
            Some(o) if !o.trim().is_empty() => o,
            // Unreachable through the public path (input validation enforces
            // a non-empty original); recorded loudly rather than skipped.
            _ => {
                findings.push(Finding::breach(
                    "RETURN-MALFORMED",
                    format!("txn:{}", t.transaction_id),
                    "return is missing a resolvable original_transaction_id".to_string(),
                ));
                continue;
            }
        };
        match resolved.get(original_id) {
            Some((ovi, winners)) if !winners.is_empty() => {
                let version = &plan.versions[*ovi];
                let shares = split_by_role_weights(version, winners, t.amount_cents)?;
                for ((rep, role), share) in winners.iter().zip(&shares) {
                    lines.push(CreditLine {
                        transaction_id: t.transaction_id.clone(),
                        links_original: Some(original_id.to_string()),
                        rep_id: rep.clone(),
                        role: role.clone(),
                        credited_cents: -share,
                    });
                    acc.entry((rep.clone(), *ovi))
                        .or_insert(RepAcc {
                            gross: 0,
                            returned: 0,
                        })
                        .returned += share;
                }
                findings.push(Finding::breach(
                    "CLAWBACK",
                    format!("txn:{}", t.transaction_id),
                    format!(
                        "return of {amount} cents on original {original} after payment reverses \
                         credited commission; clawback requires signoff",
                        amount = t.amount_cents,
                        original = original_id
                    ),
                ));
            }
            // Original was unassigned or collision-dropped: nothing to
            // reverse. Never silently ignored — a warn finding records it.
            _ => findings.push(Finding {
                rule_id: "ORIGINAL-NOT-CREDITED".to_string(),
                severity: spine::Severity::Warn,
                subject: format!("txn:{}", t.transaction_id),
                message: format!(
                    "original transaction {original_id} was not credited (unassigned or \
                     collision-dropped); return has nothing to reverse"
                ),
                requires_signoff: false,
            }),
        }
    }

    // Pass 3 — per-(rep, version) roll-up: attainment, caps, commission.
    let mut summaries: Vec<RepSummary> = Vec::new();
    for ((rep, vi), a) in acc {
        let version = &plan.versions[vi];
        let net = a.gross - a.returned;
        let attainment_ppm =
            checked_mul(net, ATTAINMENT_SCALE, "attainment")? / version.quota_cents;
        let windfall_cap_applied = version
            .windfall_cap_ppm
            .is_some_and(|cap| attainment_ppm > i128::from(cap));
        let gross_commission = commission_total(version, a.gross)?;
        let (net_commission, net_band_slices) = commission_parts(version, net.max(0))?;
        summaries.push(RepSummary {
            rep_id: rep.clone(),
            plan_version: version.version,
            band_mode: version.band_mode.clone(),
            gross_credited_cents: a.gross,
            returned_cents: a.returned,
            net_credited_cents: net,
            attainment_ppm,
            windfall_cap_ppm: version.windfall_cap_ppm,
            windfall_cap_applied,
            net_band_slices,
            gross_commission_cents: gross_commission,
            net_commission_cents: net_commission,
            clawback_commission_cents: gross_commission - net_commission,
        });
        if windfall_cap_applied {
            if let Some(cap) = version.windfall_cap_ppm {
                findings.push(Finding {
                    rule_id: "WINDFALL-CAP".to_string(),
                    severity: spine::Severity::Info,
                    subject: format!("rep:{rep}:v{}", version.version),
                    message: format!(
                        "attainment {attainment_ppm} ppm exceeds windfall cap {cap} ppm; \
                         commission basis capped"
                    ),
                    requires_signoff: false,
                });
            }
        }
    }
    summaries.sort_by(|a, b| (&a.rep_id, &a.plan_version).cmp(&(&b.rep_id, &b.plan_version)));

    // Canonical output order everywhere: identical content, any input order.
    lines.sort();
    findings.sort_by(|a, b| {
        (&a.subject, &a.rule_id, &a.message).cmp(&(&b.subject, &b.rule_id, &b.message))
    });
    Ok(EngineOutput {
        credit_lines: lines,
        rep_summaries: summaries,
        findings,
    })
}

/// Resolve the winning credits of a sale by role. Within a role, the credit
/// with the lowest `priority` number wins; an exact tie at the winning
/// priority drops the role's credit entirely and raises a breach — never
/// first-come, and input order cannot decide the outcome.
fn resolve_credit_winners(t: &Transaction, findings: &mut Vec<Finding>) -> Vec<(String, String)> {
    let mut by_role: BTreeMap<&str, Vec<&Credit>> = BTreeMap::new();
    for c in &t.credits {
        by_role.entry(c.role.as_str()).or_default().push(c);
    }
    let mut winners = Vec::new();
    for (role, credits) in by_role {
        let mut candidates = credits;
        candidates.sort_by(|a, b| (&a.priority, &a.rep_id).cmp(&(&b.priority, &b.rep_id)));
        let best = candidates[0].priority;
        if candidates.len() > 1 && candidates[1].priority == best {
            findings.push(Finding::breach(
                "CREDIT-COLLISION",
                format!("txn:{}", t.transaction_id),
                format!(
                    "role {role} has tied priority {best} on transaction {}; the role's \
                     credit is dropped (fail-closed, never first-come)",
                    t.transaction_id
                ),
            ));
            continue;
        }
        winners.push((candidates[0].rep_id.clone(), role.to_string()));
    }
    winners.sort();
    winners
}

/// Split `amount` across the winning (rep, role) credits using the version's
/// role weights. Shares are floored per credit and the leftover cents go to
/// the largest fractional remainders (largest-remainder rule), so the split
/// always sums to exactly `amount`.
fn split_by_role_weights(
    version: &PlanVersion,
    winners: &[(String, String)],
    amount: i128,
) -> Result<Vec<i128>, EngineError> {
    let mut weights = Vec::with_capacity(winners.len());
    for (_rep, role) in winners {
        let w = version
            .role_weight(role)
            .ok_or_else(|| EngineError::MissingRoleWeight {
                role: role.clone(),
                version: version.version,
            })?;
        weights.push(i128::from(w));
    }
    largest_remainder(amount, &weights)
}

/// Largest-remainder distribution of `amount` across `weights` (which sum to
/// `BASIS_POINTS` by config validation). Ties in the fractional remainder are
/// broken by index — the caller passes weights in a canonical, content-based
/// order, so the split never depends on input order.
fn largest_remainder(amount: i128, weights: &[i128]) -> Result<Vec<i128>, EngineError> {
    let total: i128 = weights.iter().sum();
    let mut shares = Vec::with_capacity(weights.len());
    for w in weights {
        shares.push(checked_mul(amount, *w, "split share")? / total);
    }
    let fracs: Vec<i128> = weights
        .iter()
        .map(|w| checked_mul(amount, *w, "split remainder").map(|v| v % total))
        .collect::<Result<_, EngineError>>()?;
    let mut order: Vec<usize> = (0..weights.len()).collect();
    order.sort_by(|&a, &b| fracs[b].cmp(&fracs[a]));
    let remainder = amount - shares.iter().sum::<i128>();
    debug_assert!(remainder >= 0);
    for &i in order.iter().take(remainder.max(0) as usize) {
        shares[i] += 1;
    }
    Ok(shares)
}

/// Commission on `revenue` with the windfall cap applied to the basis.
/// Returns the total and the band slices behind it.
fn commission_parts(v: &PlanVersion, revenue: i128) -> Result<(i128, Vec<BandSlice>), EngineError> {
    if revenue <= 0 {
        return Ok((0, Vec::new()));
    }
    let cap_rev = match v.windfall_cap_ppm {
        Some(c) => Some(
            checked_mul(i128::from(c), v.quota_cents, "windfall cap revenue")? / ATTAINMENT_SCALE,
        ),
        None => None,
    };
    let basis = cap_rev.map_or(revenue, |cap| revenue.min(cap));
    if basis <= 0 {
        return Ok((0, Vec::new()));
    }
    match v.band_mode {
        BandMode::Cliff => {
            // Rate selection uses attainment in ppm capped at the windfall
            // cap; the payout basis is the cap-consistent revenue.
            let att = checked_mul(revenue, ATTAINMENT_SCALE, "attainment")? / v.quota_cents;
            let att_capped = v
                .windfall_cap_ppm
                .map_or(att, |cap| att.min(i128::from(cap)));
            // Validation guarantees the last band is unbounded, so a band
            // always contains the attainment.
            let band_index = v
                .bands
                .iter()
                .position(|b| b.up_to_ppm.is_none_or(|up| att_capped < i128::from(up)))
                .unwrap_or(v.bands.len() - 1);
            let band = &v.bands[band_index];
            let commission = round_half_up(
                checked_mul(basis, i128::from(band.rate_bps), "band commission")?,
                BASIS_POINTS,
            );
            Ok((
                commission,
                vec![BandSlice {
                    band_index,
                    up_to_ppm: band.up_to_ppm,
                    rate_bps: band.rate_bps,
                    slice_cents: basis,
                    commission_cents: commission,
                }],
            ))
        }
        BandMode::Marginal => {
            let mut total = 0i128;
            let mut slices = Vec::new();
            let mut taken = 0i128;
            for (index, band) in v.bands.iter().enumerate() {
                let bound = match band.up_to_ppm {
                    Some(up) => {
                        checked_mul(i128::from(up), v.quota_cents, "band boundary")?
                            / ATTAINMENT_SCALE
                    }
                    None => basis,
                }
                .min(basis);
                if bound > taken {
                    let slice = bound - taken;
                    let commission = round_half_up(
                        checked_mul(slice, i128::from(band.rate_bps), "band commission")?,
                        BASIS_POINTS,
                    );
                    slices.push(BandSlice {
                        band_index: index,
                        up_to_ppm: band.up_to_ppm,
                        rate_bps: band.rate_bps,
                        slice_cents: slice,
                        commission_cents: commission,
                    });
                    total += commission;
                    taken = bound;
                }
            }
            Ok((total, slices))
        }
    }
}

fn commission_total(v: &PlanVersion, revenue: i128) -> Result<i128, EngineError> {
    commission_parts(v, revenue).map(|(total, _)| total)
}

/// Integer half-up rounding of `numerator / denominator` for non-negative
/// numerators — per-slice rounding, summed, never floats.
fn round_half_up(numerator: i128, denominator: i128) -> i128 {
    debug_assert!(denominator > 0);
    debug_assert!(numerator >= 0);
    let q = numerator / denominator;
    let r = numerator % denominator;
    if r * 2 >= denominator {
        q + 1
    } else {
        q
    }
}

fn checked_mul(a: i128, b: i128, what: &'static str) -> Result<i128, EngineError> {
    a.checked_mul(b)
        .ok_or(EngineError::ArithmeticOverflow { what })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Band, RoleWeight};
    use crate::input::Credit;
    use chrono::NaiveDate;

    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("valid date")
    }

    fn band(up_to_ppm: Option<u64>, rate_bps: u32) -> Band {
        Band {
            up_to_ppm,
            rate_bps,
        }
    }

    /// Quota 1_000_000c; marginal bands 100% @200, 200% @350, above @500.
    fn marginal_plan() -> PlanConfig {
        PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![PlanVersion {
                version: 1,
                effective_from: date("2026-01-01"),
                effective_to: None,
                quota_cents: 1_000_000,
                band_mode: BandMode::Marginal,
                bands: vec![
                    band(Some(1_000_000), 200),
                    band(Some(2_000_000), 350),
                    band(None, 500),
                ],
                windfall_cap_ppm: None,
                max_spread_bps: None,
                role_weights: vec![RoleWeight {
                    role: "ae".to_string(),
                    weight_bps: 10_000,
                }],
            }],
        }
    }

    fn sale(id: &str, day: &str, amount: i128, credits: Vec<Credit>) -> Transaction {
        Transaction {
            transaction_id: id.to_string(),
            date: date(day),
            amount_cents: amount,
            kind: TxnKind::Sale,
            original_transaction_id: None,
            credits,
        }
    }

    fn file(txns: Vec<Transaction>) -> TransactionsFile {
        TransactionsFile { transactions: txns }
    }

    fn single_credit(rep: &str) -> Vec<Credit> {
        vec![Credit {
            rep_id: rep.to_string(),
            role: "ae".to_string(),
            priority: 1,
        }]
    }

    #[test]
    fn round_half_up_at_the_midpoint() {
        assert_eq!(round_half_up(50, 100), 1); // exactly .5 → up
        assert_eq!(round_half_up(49, 100), 0);
        assert_eq!(round_half_up(150, 100), 2);
    }

    #[test]
    fn marginal_mode_pays_each_slice_at_its_own_rate() {
        let plan = marginal_plan();
        let out = run(
            &plan,
            &file(vec![sale(
                "T1",
                "2026-02-01",
                2_000_000,
                single_credit("r"),
            )]),
        )
        .expect("runs");
        assert_eq!(out.rep_summaries[0].net_commission_cents, 55_000);
        assert_eq!(out.rep_summaries[0].net_band_slices.len(), 2);
    }

    #[test]
    fn cliff_mode_pays_all_revenue_at_the_landing_band_rate() {
        let mut plan = marginal_plan();
        plan.versions[0].band_mode = BandMode::Cliff;
        let out = run(
            &plan,
            &file(vec![sale(
                "T1",
                "2026-02-01",
                2_500_000,
                single_credit("r"),
            )]),
        )
        .expect("runs");
        // Attainment 250% lands in the open band: all revenue at 500 bps.
        assert_eq!(out.rep_summaries[0].net_commission_cents, 125_000);
        assert_eq!(out.rep_summaries[0].net_band_slices[0].band_index, 2);
    }

    #[test]
    fn marginal_and_cliff_diverge_on_the_same_input() {
        let mut plan = marginal_plan();
        let txns = file(vec![sale(
            "T1",
            "2026-02-01",
            1_500_000,
            single_credit("r"),
        )]);
        let marginal = run(&plan, &txns).expect("runs");
        plan.versions[0].band_mode = BandMode::Cliff;
        let cliff = run(&plan, &txns).expect("runs");
        // Marginal: 1_000_000@200 + 500_000@350 = 20_000 + 17_500.
        assert_eq!(marginal.rep_summaries[0].net_commission_cents, 37_500);
        // Cliff: all 1_500_000 at the 350 band = 52_500.
        assert_eq!(cliff.rep_summaries[0].net_commission_cents, 52_500);
    }

    #[test]
    fn attainment_exactly_at_a_band_boundary_selects_the_next_band_for_cliff() {
        let mut plan = marginal_plan();
        plan.versions[0].band_mode = BandMode::Cliff;
        let out = run(
            &plan,
            &file(vec![sale(
                "T1",
                "2026-02-01",
                1_000_000,
                single_credit("r"),
            )]),
        )
        .expect("runs");
        // up_to is exclusive: exactly 100% lands in the 350 band.
        assert_eq!(out.rep_summaries[0].net_commission_cents, 35_000);
    }

    #[test]
    fn attainment_exactly_at_a_band_boundary_pays_only_the_lower_slice_for_marginal() {
        let plan = marginal_plan();
        let out = run(
            &plan,
            &file(vec![sale(
                "T1",
                "2026-02-01",
                1_000_000,
                single_credit("r"),
            )]),
        )
        .expect("runs");
        assert_eq!(out.rep_summaries[0].net_band_slices.len(), 1);
        assert_eq!(out.rep_summaries[0].net_commission_cents, 20_000);
    }

    #[test]
    fn windfall_cap_caps_commission_and_raises_an_info_finding() {
        let mut plan = marginal_plan();
        plan.versions[0].windfall_cap_ppm = Some(1_200_000);
        let out = run(
            &plan,
            &file(vec![sale(
                "T1",
                "2026-02-01",
                2_000_000,
                single_credit("r"),
            )]),
        )
        .expect("runs");
        let s = &out.rep_summaries[0];
        assert!(s.windfall_cap_applied);
        assert_eq!(s.net_commission_cents, 27_000); // 1_000_000@200 + 200_000@350
        assert!(out
            .findings
            .iter()
            .any(|f| f.rule_id == "WINDFALL-CAP" && f.severity == spine::Severity::Info));
    }

    #[test]
    fn windfall_cap_at_exact_boundary_is_not_applied() {
        let mut plan = marginal_plan();
        plan.versions[0].windfall_cap_ppm = Some(1_500_000);
        let out = run(
            &plan,
            &file(vec![sale(
                "T1",
                "2026-02-01",
                1_500_000,
                single_credit("r"),
            )]),
        )
        .expect("runs");
        assert!(!out.rep_summaries[0].windfall_cap_applied);
        assert_eq!(out.rep_summaries[0].net_commission_cents, 37_500);
        assert!(!out.findings.iter().any(|f| f.rule_id == "WINDFALL-CAP"));
    }

    #[test]
    fn split_rounding_uses_largest_remainder_and_sums_exactly() {
        let mut plan = marginal_plan();
        plan.versions[0].role_weights = vec![
            RoleWeight {
                role: "ae".to_string(),
                weight_bps: 5_000,
            },
            RoleWeight {
                role: "se".to_string(),
                weight_bps: 5_000,
            },
        ];
        let txns = file(vec![sale(
            "T1",
            "2026-02-01",
            101,
            vec![
                Credit {
                    rep_id: "rep-z".to_string(),
                    role: "se".to_string(),
                    priority: 1,
                },
                Credit {
                    rep_id: "rep-a".to_string(),
                    role: "ae".to_string(),
                    priority: 1,
                },
            ],
        )]);
        let out = run(&plan, &txns).expect("runs");
        let by_rep: BTreeMap<String, i128> = out
            .credit_lines
            .iter()
            .map(|l| (l.rep_id.clone(), l.credited_cents))
            .collect();
        // Both remainders tie at 50; the extra cent goes to the canonical
        // (rep, role) order — rep-a — never to input order.
        assert_eq!(by_rep["rep-a"], 51);
        assert_eq!(by_rep["rep-z"], 50);
        assert_eq!(by_rep.values().sum::<i128>(), 101);
    }

    #[test]
    fn credit_collision_resolves_by_explicit_priority() {
        let plan = marginal_plan();
        let txns = file(vec![sale(
            "T1",
            "2026-02-01",
            100_000,
            vec![
                Credit {
                    rep_id: "rep-b".to_string(),
                    role: "ae".to_string(),
                    priority: 2,
                },
                Credit {
                    rep_id: "rep-a".to_string(),
                    role: "ae".to_string(),
                    priority: 1,
                },
            ],
        )]);
        let out = run(&plan, &txns).expect("runs");
        assert_eq!(out.credit_lines.len(), 1);
        assert_eq!(out.credit_lines[0].rep_id, "rep-a");
        assert!(out.findings.is_empty());
    }

    #[test]
    fn collision_tie_drops_the_role_and_is_order_independent() {
        let plan = marginal_plan();
        let mk = |reverse: bool| {
            let mut credits = vec![
                Credit {
                    rep_id: "rep-a".to_string(),
                    role: "ae".to_string(),
                    priority: 1,
                },
                Credit {
                    rep_id: "rep-b".to_string(),
                    role: "ae".to_string(),
                    priority: 1,
                },
            ];
            if reverse {
                credits.reverse();
            }
            file(vec![sale("T1", "2026-02-01", 100_000, credits)])
        };
        let a = run(&plan, &mk(false)).expect("runs");
        let b = run(&plan, &mk(true)).expect("runs");
        // Identical output — input order decided nothing.
        assert_eq!(a.credit_lines, b.credit_lines);
        assert_eq!(a.rep_summaries, b.rep_summaries);
        assert_eq!(a.findings.len(), b.findings.len());
        assert!(a
            .findings
            .iter()
            .zip(b.findings.iter())
            .all(|(x, y)| x.rule_id == y.rule_id && x.subject == y.subject));
        assert!(a.credit_lines.is_empty()); // the tied role is dropped whole
        let finding = a
            .findings
            .iter()
            .find(|f| f.rule_id == "CREDIT-COLLISION")
            .expect("collision finding present");
        assert_eq!(finding.severity, spine::Severity::Breach);
        assert!(finding.requires_signoff);
        assert_eq!(finding.subject, "txn:T1");
    }
}
