//! Pure matching engine for bankrec-spine.
//!
//! Deterministic tiered reconciliation of bank statement lines against
//! cash-account ledger entries:
//!
//! 1. **Exact** — identical canonical amount and identical reference.
//! 2. **Tolerance** — same reference, amount within a configured ± cent
//!    window; smallest variance wins, ties resolved by input order.
//! 3. **Many-to-one** — N ledger lines (2 ≤ N ≤ max_group_size, spec caps
//!    N at 5) whose sum lands within tolerance of one statement line.
//!    Candidates are canonically ordered (date, reference, input order)
//!    and bounded, so identical inputs always produce identical groupings.
//!
//! Plus: duplicate statement-line detection (same reference, amount, and
//! date → warn) and the stale-item rule (unmatched items older than
//! `stale_days` escalate from warn to breach severity).
//!
//! Every function is pure over explicit inputs — no clock, no filesystem,
//! no network, no randomness. Money is integer cents (i128); time enters
//! only as caller-supplied dates.

use std::collections::BTreeMap;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use spine::{Finding, Severity};

use crate::config::BankrecConfig;
use crate::inputs::ValidatedInputs;

/// Rule id: unmatched statement line (severity escalates when stale).
pub const RULE_STMT_UNMATCHED: &str = "stmt-unmatched";
/// Rule id: unmatched ledger entry (severity escalates when stale).
pub const RULE_LEDGER_UNMATCHED: &str = "ledger-unmatched";
/// Rule id: duplicate statement line (same reference, amount, and date).
pub const RULE_STMT_DUPLICATE: &str = "stmt-duplicate";

pub const RULE_LEDGER_DUPLICATE: &str = "ledger-duplicate";

/// Smallest many-to-one group size; a single ledger line is the
/// exact/tolerance tiers' job.
pub const MIN_GROUP_SIZE: usize = 2;

/// Which pass produced a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchTier {
    Exact,
    Tolerance,
    ManyToOne,
}

/// Which side of the reconciliation an unmatched item came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Statement,
    Ledger,
}

/// One resolved match: a statement line and the ledger line(s) that cover
/// it, with the matched sum and the residual variance in cents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRecord {
    pub tier: MatchTier,
    pub statement_id: String,
    pub ledger_ids: Vec<String>,
    pub statement_amount_cents: i128,
    pub matched_amount_cents: i128,
    pub variance_cents: i128,
}

/// An item neither side could match — the unmatched-items ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmatchedItem {
    pub id: String,
    pub side: Side,
    pub date: String,
    pub age_days: i64,
    pub stale: bool,
}

/// Typed adjustment proposal. Proposals are advisory; a human executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// Money moved at the bank with no ledger entry — record it.
    RecordLedgerEntry,
    /// Books record money movement the bank does not show — investigate
    /// (timing difference or book error).
    InvestigateLedgerEntry,
}

/// An adjustment proposal derived from an unmatched item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjustmentProposal {
    pub kind: ProposalKind,
    pub subject: String,
    pub detail: String,
}

/// Full output of one reconciliation run. Deterministic for identical
/// inputs, config, and as-of date.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub as_of: String,
    pub matches: Vec<MatchRecord>,
    pub unmatched_statement: Vec<UnmatchedItem>,
    pub unmatched_ledger: Vec<UnmatchedItem>,
    pub adjustment_proposals: Vec<AdjustmentProposal>,
    pub findings: Vec<Finding>,
}

/// Run the reconciliation. Infallible: inputs arrive validated and
/// normalized by [`crate::inputs::parse_inputs`].
pub fn compute(
    inputs: &ValidatedInputs,
    config: &BankrecConfig,
    as_of: NaiveDate,
) -> ReconciliationReport {
    let statements = &inputs.statements;
    let ledgers = &inputs.ledgers;
    let tolerance = i128::from(config.tolerance_cents);

    let mut findings = duplicate_findings(statements);
    findings.extend(duplicate_ledger_findings(ledgers));

    let mut consumed_statement = vec![false; statements.len()];
    let mut consumed_ledger = vec![false; ledgers.len()];
    let mut matches = Vec::new();

    // Pass 1 — exact: identical canonical amount and identical reference.
    for s in 0..statements.len() {
        if consumed_statement[s] {
            continue;
        }
        let hit = (0..ledgers.len()).find(|&l| {
            !consumed_ledger[l]
                && ledgers[l].reference == statements[s].reference
                && ledgers[l].amount == statements[s].amount
        });
        if let Some(l) = hit {
            consumed_statement[s] = true;
            consumed_ledger[l] = true;
            matches.push(MatchRecord {
                tier: MatchTier::Exact,
                statement_id: statements[s].id.clone(),
                ledger_ids: vec![ledgers[l].id.clone()],
                statement_amount_cents: statements[s].amount,
                matched_amount_cents: ledgers[l].amount,
                variance_cents: 0,
            });
        }
    }

    // Pass 2 — tolerance: same reference, amount within ±tolerance; the
    // smallest absolute variance wins, ties resolved by input order.
    for s in 0..statements.len() {
        if consumed_statement[s] {
            continue;
        }
        let mut best: Option<(i128, usize)> = None;
        for l in 0..ledgers.len() {
            if consumed_ledger[l] || ledgers[l].reference != statements[s].reference {
                continue;
            }
            let abs_variance = (ledgers[l].amount - statements[s].amount).abs();
            if abs_variance > tolerance {
                continue;
            }
            let better = match best {
                None => true,
                Some((best_abs, _)) => abs_variance < best_abs,
            };
            if better {
                best = Some((abs_variance, l));
            }
        }
        if let Some((_, l)) = best {
            consumed_statement[s] = true;
            consumed_ledger[l] = true;
            matches.push(MatchRecord {
                tier: MatchTier::Tolerance,
                statement_id: statements[s].id.clone(),
                ledger_ids: vec![ledgers[l].id.clone()],
                statement_amount_cents: statements[s].amount,
                matched_amount_cents: ledgers[l].amount,
                variance_cents: ledgers[l].amount - statements[s].amount,
            });
        }
    }

    // Pass 3 — many-to-one: N ledger lines sum to one statement line within
    // tolerance. Same-sign candidates only, canonically ordered and bounded
    // for deterministic grouping.
    for s in 0..statements.len() {
        if consumed_statement[s] {
            continue;
        }
        let target = statements[s].amount;
        let positive = target > 0;
        // Optional date-proximity constraint: when
        // `many_to_one_date_window_days` is set, only ledger entries within
        // that many days of the statement line (either direction) are
        // eligible — prevents groups that silently pair a fresh statement
        // line with long-outstanding open items.
        let in_window = |l: usize| match config.many_to_one_date_window_days {
            None => true,
            Some(w) => (ledgers[l].date - statements[s].date).num_days().abs() <= w,
        };
        let mut candidates: Vec<usize> = (0..ledgers.len())
            .filter(|&l| !consumed_ledger[l] && (ledgers[l].amount > 0) == positive && in_window(l))
            .collect();
        // Canonical candidate order: date, then reference, then input order.
        candidates.sort_by(|&a, &b| {
            ledgers[a]
                .date
                .cmp(&ledgers[b].date)
                .then_with(|| ledgers[a].reference.cmp(&ledgers[b].reference))
                .then(a.cmp(&b))
        });
        candidates
            .truncate(usize::try_from(config.many_to_one_candidate_cap).unwrap_or(usize::MAX));
        if let Some(group) = find_group(
            &candidates,
            ledgers,
            target,
            tolerance,
            config.max_group_size,
        ) {
            let matched_sum: i128 = group.iter().map(|&l| ledgers[l].amount).sum();
            consumed_statement[s] = true;
            for &l in &group {
                consumed_ledger[l] = true;
            }
            matches.push(MatchRecord {
                tier: MatchTier::ManyToOne,
                statement_id: statements[s].id.clone(),
                ledger_ids: group.iter().map(|&l| ledgers[l].id.clone()).collect(),
                statement_amount_cents: target,
                matched_amount_cents: matched_sum,
                variance_cents: matched_sum - target,
            });
        }
    }

    // Unmatched items, findings, and proposals — statement side, then
    // ledger side, each in input order.
    let mut unmatched_statement = Vec::new();
    for (s, st) in statements.iter().enumerate() {
        if consumed_statement[s] {
            continue;
        }
        let age_days = (as_of - st.date).num_days();
        let stale = age_days > config.stale_days;
        unmatched_statement.push(UnmatchedItem {
            id: st.id.clone(),
            side: Side::Statement,
            date: st.date.to_string(),
            age_days,
            stale,
        });
        if stale {
            findings.push(Finding::breach(
                RULE_STMT_UNMATCHED,
                st.id.clone(),
                format!(
                    "unmatched statement line for {} (ref {}) is {age_days} days old, past the {}-day stale threshold",
                    fmt_cents(st.amount),
                    st.reference,
                    config.stale_days
                ),
            ));
        } else {
            findings.push(Finding {
                rule_id: RULE_STMT_UNMATCHED.to_string(),
                severity: Severity::Warn,
                subject: st.id.clone(),
                message: format!(
                    "unmatched statement line for {} (ref {}) is {age_days} days old",
                    fmt_cents(st.amount),
                    st.reference
                ),
                requires_signoff: false,
            });
        }
    }

    let mut unmatched_ledger = Vec::new();
    for (l, le) in ledgers.iter().enumerate() {
        if consumed_ledger[l] {
            continue;
        }
        let age_days = (as_of - le.date).num_days();
        let stale = age_days > config.stale_days;
        unmatched_ledger.push(UnmatchedItem {
            id: le.id.clone(),
            side: Side::Ledger,
            date: le.date.to_string(),
            age_days,
            stale,
        });
        if stale {
            findings.push(Finding::breach(
                RULE_LEDGER_UNMATCHED,
                le.id.clone(),
                format!(
                    "unmatched ledger entry for {} (ref {}) is {age_days} days old, past the {}-day stale threshold",
                    fmt_cents(le.amount),
                    le.reference,
                    config.stale_days
                ),
            ));
        } else {
            findings.push(Finding {
                rule_id: RULE_LEDGER_UNMATCHED.to_string(),
                severity: Severity::Warn,
                subject: le.id.clone(),
                message: format!(
                    "unmatched ledger entry for {} (ref {}) is {age_days} days old",
                    fmt_cents(le.amount),
                    le.reference
                ),
                requires_signoff: false,
            });
        }
    }

    let mut adjustment_proposals = Vec::new();
    for u in &unmatched_statement {
        adjustment_proposals.push(AdjustmentProposal {
            kind: ProposalKind::RecordLedgerEntry,
            subject: u.id.clone(),
            detail: "money moved at the bank with no ledger entry — record it or classify \
                     (timing difference, error, or fraud)"
                .to_string(),
        });
    }
    for u in &unmatched_ledger {
        adjustment_proposals.push(AdjustmentProposal {
            kind: ProposalKind::InvestigateLedgerEntry,
            subject: u.id.clone(),
            detail: "recorded in the books but not matched at the bank — confirm timing \
                     difference or correct the books"
                .to_string(),
        });
    }

    ReconciliationReport {
        as_of: as_of.to_string(),
        matches,
        unmatched_statement,
        unmatched_ledger,
        adjustment_proposals,
        findings,
    }
}

/// Duplicate item detection, shared by the statement-side and ledger-side
/// rules: same reference, canonical amount, and date → a warn finding on
/// every occurrence after the first. BTreeMap keeps the finding order
/// deterministic (sorted by reference, amount, date).
fn duplicate_rows_findings(
    rows: &[(String, String, i128, NaiveDate)],
    rule_id: &str,
    noun: &str,
) -> Vec<Finding> {
    let mut groups: BTreeMap<(&str, i128, NaiveDate), Vec<usize>> = BTreeMap::new();
    for (i, (_id, reference, amount, date)) in rows.iter().enumerate() {
        groups
            .entry((reference.as_str(), *amount, *date))
            .or_default()
            .push(i);
    }
    let mut findings = Vec::new();
    for (_key, indexes) in groups {
        if indexes.len() < 2 {
            continue;
        }
        let first = indexes[0];
        for &i in &indexes[1..] {
            let (id, reference, _, date) = &rows[i];
            findings.push(Finding {
                rule_id: rule_id.to_string(),
                severity: Severity::Warn,
                subject: id.clone(),
                message: format!(
                    "duplicate {noun}: same reference ({reference}) and date ({date}) as {}",
                    rows[first].0
                ),
                requires_signoff: false,
            });
        }
    }
    findings
}

fn duplicate_findings(statements: &[crate::inputs::CanonicalStatement]) -> Vec<Finding> {
    let rows: Vec<(String, String, i128, NaiveDate)> = statements
        .iter()
        .map(|s| (s.id.clone(), s.reference.clone(), s.amount, s.date))
        .collect();
    duplicate_rows_findings(&rows, RULE_STMT_DUPLICATE, "statement line")
}

/// A duplicate ledger entry is a double-posting — the more serious control
/// failure on the books side — but the response is the same warn-tier
/// treatment so the human close sees it before the pack seals.
fn duplicate_ledger_findings(ledgers: &[crate::inputs::CanonicalLedger]) -> Vec<Finding> {
    let rows: Vec<(String, String, i128, NaiveDate)> = ledgers
        .iter()
        .map(|l| (l.id.clone(), l.reference.clone(), l.amount, l.date))
        .collect();
    duplicate_rows_findings(&rows, RULE_LEDGER_DUPLICATE, "ledger entry")
}

/// Bounded same-sign subset search: the first group of `MIN_GROUP_SIZE`
/// to `max_size` candidates (in the canonical order given) whose sum lands
/// within `tolerance` of `target`. Include-first depth-first search with
/// monotone pruning — deterministic for identical inputs.
fn find_group(
    candidates: &[usize],
    ledgers: &[crate::inputs::CanonicalLedger],
    target: i128,
    tolerance: i128,
    max_size: u8,
) -> Option<Vec<usize>> {
    let positive = target > 0;
    let max_size = usize::from(max_size);
    let mut chosen = Vec::new();

    #[allow(clippy::too_many_arguments)] // recursion carrier: parameters mirror the subproblem
    fn dfs(
        candidates: &[usize],
        ledgers: &[crate::inputs::CanonicalLedger],
        target: i128,
        tolerance: i128,
        max_size: usize,
        positive: bool,
        start: usize,
        partial: i128,
        chosen: &mut Vec<usize>,
    ) -> Option<Vec<usize>> {
        if chosen.len() >= MIN_GROUP_SIZE && (partial - target).abs() <= tolerance {
            return Some(chosen.clone());
        }
        if chosen.len() == max_size {
            return None;
        }
        // Same-sign candidates only: the partial sum moves monotonically,
        // so once it overshoots the window the branch is dead.
        if positive && partial > target + tolerance {
            return None;
        }
        if !positive && partial < target - tolerance {
            return None;
        }
        for i in start..candidates.len() {
            let next = partial + ledgers[candidates[i]].amount;
            if positive && next > target + tolerance {
                continue;
            }
            if !positive && next < target - tolerance {
                continue;
            }
            chosen.push(candidates[i]);
            if let Some(group) = dfs(
                candidates,
                ledgers,
                target,
                tolerance,
                max_size,
                positive,
                i + 1,
                next,
                chosen,
            ) {
                return Some(group);
            }
            chosen.pop();
        }
        None
    }

    dfs(
        candidates,
        ledgers,
        target,
        tolerance,
        max_size,
        positive,
        0,
        0,
        &mut chosen,
    )
}

/// Format integer cents as a signed decimal string, e.g. -125050 →
/// "-1250.50". No floating point anywhere.
pub fn fmt_cents(cents: i128) -> String {
    let sign = if cents < 0 { '-' } else { '+' };
    let abs = cents.unsigned_abs();
    format!("{sign}{}.{:02}", abs / 100, abs % 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inputs::{CanonicalLedger, CanonicalStatement};
    use chrono::NaiveDate;

    fn as_of() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 9, 22).unwrap()
    }

    fn config(tolerance: i64) -> BankrecConfig {
        BankrecConfig {
            tolerance_cents: tolerance,
            max_group_size: 5,
            stale_days: 14,
            many_to_one_candidate_cap: 100,
            many_to_one_date_window_days: None,
        }
    }

    fn st(id: &str, date: &str, reference: &str, amount: i128) -> CanonicalStatement {
        CanonicalStatement {
            id: id.to_string(),
            date: NaiveDate::parse_from_str(date, "%Y-%m-%d").unwrap(),
            reference: reference.to_string(),
            amount,
        }
    }

    fn ld(id: &str, date: &str, reference: &str, amount: i128) -> CanonicalLedger {
        CanonicalLedger {
            id: id.to_string(),
            date: NaiveDate::parse_from_str(date, "%Y-%m-%d").unwrap(),
            reference: reference.to_string(),
            amount,
        }
    }

    fn run(
        statements: Vec<CanonicalStatement>,
        ledgers: Vec<CanonicalLedger>,
        config: &BankrecConfig,
    ) -> ReconciliationReport {
        let inputs = ValidatedInputs {
            statements,
            ledgers,
        };
        compute(&inputs, config, as_of())
    }

    // --- exact tier ---

    #[test]
    fn exact_tier_matches_amount_and_reference() {
        let r = run(
            vec![st("S1", "2026-09-01", "WIRE-1", 125_000)],
            vec![ld("L1", "2026-09-01", "WIRE-1", 125_000)],
            &config(0),
        );
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].tier, MatchTier::Exact);
        assert_eq!(r.matches[0].ledger_ids, vec!["L1"]);
        assert_eq!(r.matches[0].variance_cents, 0);
        assert!(r.unmatched_statement.is_empty());
        assert!(r.unmatched_ledger.is_empty());
    }

    #[test]
    fn exact_tier_misses_on_reference_mismatch() {
        let r = run(
            vec![st("S1", "2026-09-01", "WIRE-1", 125_000)],
            vec![ld("L1", "2026-09-01", "WIRE-2", 125_000)],
            &config(0),
        );
        assert!(r.matches.is_empty());
        assert_eq!(r.unmatched_statement.len(), 1);
        assert_eq!(r.unmatched_ledger.len(), 1);
    }

    #[test]
    fn exact_tier_misses_on_amount_mismatch() {
        let r = run(
            vec![st("S1", "2026-09-01", "WIRE-1", 125_000)],
            vec![ld("L1", "2026-09-01", "WIRE-1", 125_001)],
            &config(0),
        );
        assert!(r.matches.is_empty());
        assert_eq!(r.unmatched_statement.len(), 1);
    }

    // --- tolerance tier ---

    #[test]
    fn tolerance_tier_matches_within_window() {
        // Bank charge of 25 cents: statement shows the round amount, the
        // ledger entry is 25 cents short.
        let r = run(
            vec![st("S1", "2026-09-01", "FEE", 100_000)],
            vec![ld("L1", "2026-09-01", "FEE", 99_975)],
            &config(100),
        );
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].tier, MatchTier::Tolerance);
        assert_eq!(r.matches[0].variance_cents, -25);
    }

    #[test]
    fn tolerance_boundary_at_plus_tolerance_matches() {
        let r = run(
            vec![st("S1", "2026-09-01", "FEE", 100_000)],
            vec![ld("L1", "2026-09-01", "FEE", 100_100)],
            &config(100),
        );
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].variance_cents, 100);
    }

    #[test]
    fn tolerance_beyond_boundary_misses() {
        let r = run(
            vec![st("S1", "2026-09-01", "FEE", 100_000)],
            vec![ld("L1", "2026-09-01", "FEE", 100_101)],
            &config(100),
        );
        assert!(r.matches.is_empty());
        assert_eq!(r.unmatched_statement.len(), 1);
        assert_eq!(r.unmatched_ledger.len(), 1);
    }

    #[test]
    fn tolerance_tier_misses_on_reference_mismatch() {
        // Within tolerance but the references differ: no match.
        let r = run(
            vec![st("S1", "2026-09-01", "FEE", 100_000)],
            vec![ld("L1", "2026-09-01", "OTHER", 100_000)],
            &config(100),
        );
        assert!(r.matches.is_empty());
    }

    #[test]
    fn tolerance_tier_prefers_smallest_variance() {
        let r = run(
            vec![st("S1", "2026-09-01", "FEE", 100_000)],
            vec![
                ld("L1", "2026-09-01", "FEE", 100_050),
                ld("L2", "2026-09-01", "FEE", 100_010),
            ],
            &config(100),
        );
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].ledger_ids, vec!["L2"]);
        assert_eq!(r.matches[0].variance_cents, 10);
        // The near-miss candidate stays unmatched and visible.
        assert_eq!(r.unmatched_ledger.len(), 1);
        assert_eq!(r.unmatched_ledger[0].id, "L1");
    }

    // --- sign normalization ---

    #[test]
    fn statement_debit_matches_ledger_credit() {
        // A bank withdrawal (statement -500.00) is a credit to cash in the
        // books (canonical -500.00). Normalization must land both on the
        // same canonical sign.
        let r = run(
            vec![st("S1", "2026-09-01", "PAY-9", -50_000)],
            vec![ld("L1", "2026-09-01", "PAY-9", -50_000)], // credit of 500.00 magnitude
            &config(0),
        );
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].tier, MatchTier::Exact);
        assert_eq!(r.matches[0].statement_amount_cents, -50_000);
        assert_eq!(r.matches[0].matched_amount_cents, -50_000);
    }

    // --- many-to-one tier ---

    #[test]
    fn many_to_one_matches_sum_within_tolerance() {
        // One deposit covering three invoices.
        let r = run(
            vec![st("S1", "2026-09-05", "DEP-77", 300_000)],
            vec![
                ld("L1", "2026-09-04", "INV-1", 100_000),
                ld("L2", "2026-09-04", "INV-2", 120_000),
                ld("L3", "2026-09-05", "INV-3", 80_000),
            ],
            &config(0),
        );
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].tier, MatchTier::ManyToOne);
        assert_eq!(r.matches[0].ledger_ids, vec!["L1", "L2", "L3"]);
        assert_eq!(r.matches[0].matched_amount_cents, 300_000);
        assert_eq!(r.matches[0].variance_cents, 0);
        assert!(r.unmatched_ledger.is_empty());
    }

    #[test]
    fn many_to_one_grouping_is_deterministic() {
        // Two disjoint groups both sum to the target; the canonical order
        // (date, reference) pins which one is chosen, and rerunning the
        // same inputs — or permuting their input order — must not change
        // the grouping.
        let build = |swap: bool| {
            let mut ledgers = vec![
                ld("L1", "2026-09-01", "A", 20_000),
                ld("L2", "2026-09-02", "B", 30_000),
                ld("L3", "2026-09-03", "C", 25_000),
                ld("L4", "2026-09-04", "D", 25_000),
            ];
            if swap {
                ledgers.reverse();
            }
            run(
                vec![st("S1", "2026-09-05", "DEP-9", 50_000)],
                ledgers,
                &config(0),
            )
        };
        let a = build(false);
        let b = build(false);
        let c = build(true);
        assert_eq!(a.matches, b.matches);
        assert_eq!(a.matches, c.matches);
        assert_eq!(a.matches[0].tier, MatchTier::ManyToOne);
        assert_eq!(a.matches[0].ledger_ids, vec!["L1", "L2"]);
    }

    #[test]
    fn many_to_one_respects_max_group_size() {
        // Six lines would be needed; the spec caps N at 5.
        let r = run(
            vec![st("S1", "2026-09-05", "DEP-9", 60_000)],
            vec![
                ld("L1", "2026-09-01", "A", 10_000),
                ld("L2", "2026-09-01", "B", 10_000),
                ld("L3", "2026-09-01", "C", 10_000),
                ld("L4", "2026-09-01", "D", 10_000),
                ld("L5", "2026-09-01", "E", 10_000),
                ld("L6", "2026-09-01", "F", 10_000),
            ],
            &config(0),
        );
        assert!(r.matches.is_empty());
        assert_eq!(r.unmatched_statement.len(), 1);
        assert_eq!(r.unmatched_ledger.len(), 6);
    }

    #[test]
    fn many_to_one_misses_outside_tolerance() {
        let r = run(
            vec![st("S1", "2026-09-05", "DEP-9", 50_000)],
            vec![
                ld("L1", "2026-09-01", "A", 20_000),
                ld("L2", "2026-09-02", "B", 20_000),
            ],
            &config(100),
        );
        assert!(r.matches.is_empty());
    }

    // --- duplicates ---

    #[test]
    fn duplicate_statement_lines_warn() {
        let r = run(
            vec![
                st("S1", "2026-09-01", "DUP", 45_000),
                st("S2", "2026-09-01", "DUP", 45_000),
            ],
            vec![ld("L1", "2026-09-01", "DUP", 45_000)],
            &config(0),
        );
        // Duplicates warn but still participate in matching.
        let dup: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f.rule_id == RULE_STMT_DUPLICATE)
            .collect();
        assert_eq!(dup.len(), 1);
        assert_eq!(dup[0].severity, Severity::Warn);
        assert_eq!(dup[0].subject, "S2");
        assert!(!dup[0].requires_signoff);
    }

    #[test]
    fn duplicate_warning_requires_same_date() {
        let r = run(
            vec![
                st("S1", "2026-09-01", "DUP", 45_000),
                st("S2", "2026-09-02", "DUP", 45_000),
            ],
            vec![],
            &config(0),
        );
        assert!(!r.findings.iter().any(|f| f.rule_id == RULE_STMT_DUPLICATE));
    }

    #[test]
    fn duplicate_three_occurrences_two_warnings() {
        let r = run(
            vec![
                st("S1", "2026-09-01", "DUP", 45_000),
                st("S2", "2026-09-01", "DUP", 45_000),
                st("S3", "2026-09-01", "DUP", 45_000),
            ],
            vec![],
            &config(0),
        );
        assert_eq!(
            r.findings
                .iter()
                .filter(|f| f.rule_id == RULE_STMT_DUPLICATE)
                .count(),
            2
        );
    }

    #[test]
    fn duplicate_ledger_entries_warn() {
        let r = run(
            vec![],
            vec![
                ld("L1", "2026-09-01", "DUP", 45_000),
                ld("L2", "2026-09-01", "DUP", 45_000),
            ],
            &config(0),
        );
        // A double-posted ledger entry warns on the later occurrence but
        // still participates in matching.
        let dup: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f.rule_id == RULE_LEDGER_DUPLICATE)
            .collect();
        assert_eq!(dup.len(), 1);
        assert_eq!(dup[0].severity, Severity::Warn);
        assert_eq!(dup[0].subject, "L2");
        assert!(!dup[0].requires_signoff);
    }

    #[test]
    fn duplicate_ledger_entries_require_same_date() {
        let r = run(
            vec![],
            vec![
                ld("L1", "2026-09-01", "DUP", 45_000),
                ld("L2", "2026-09-02", "DUP", 45_000),
            ],
            &config(0),
        );
        assert!(!r
            .findings
            .iter()
            .any(|f| f.rule_id == RULE_LEDGER_DUPLICATE));
    }

    #[test]
    fn many_to_one_respects_date_window_when_configured() {
        // L2 is 7 days before the statement line — outside a 3-day window.
        let statements = vec![st("S1", "2026-09-22", "BATCH", 10_000)];
        let ledgers = vec![
            ld("L1", "2026-09-21", "A", 6_000),
            ld("L2", "2026-09-15", "B", 4_000),
        ];

        // Seed default (no window): the sum-group match succeeds.
        let unwindowed = BankrecConfig {
            many_to_one_date_window_days: None,
            ..config(0)
        };
        let r = run(statements.clone(), ledgers.clone(), &unwindowed);
        assert!(r
            .matches
            .iter()
            .any(|m| m.tier == MatchTier::ManyToOne && m.statement_id == "S1"));

        // With a 3-day window, L2 is ineligible and S1 stays unmatched.
        let windowed = BankrecConfig {
            many_to_one_date_window_days: Some(3),
            ..config(0)
        };
        let r = run(statements, ledgers, &windowed);
        assert!(r.matches.iter().all(|m| m.tier != MatchTier::ManyToOne));
        assert!(r.unmatched_statement.iter().any(|u| u.id == "S1"));
        assert!(r.unmatched_ledger.iter().any(|u| u.id == "L2"));
    }

    #[test]
    fn many_to_one_date_window_boundary_is_inclusive() {
        // L1 is exactly 3 days before the statement line — at the window
        // edge, still eligible ("within this many days").
        let r = run(
            vec![st("S1", "2026-09-22", "BATCH", 10_000)],
            vec![
                ld("L1", "2026-09-19", "A", 6_000),
                ld("L2", "2026-09-22", "B", 4_000),
            ],
            &BankrecConfig {
                many_to_one_date_window_days: Some(3),
                ..config(0)
            },
        );
        assert!(r
            .matches
            .iter()
            .any(|m| m.tier == MatchTier::ManyToOne && m.statement_id == "S1"));
    }

    // --- stale escalation ---

    #[test]
    fn fresh_unmatched_statement_is_warn() {
        let r = run(
            vec![st("S1", "2026-09-20", "NEW", 10_000)],
            vec![],
            &config(0), // stale_days 14
        );
        assert!(!r.unmatched_statement[0].stale);
        assert_eq!(r.unmatched_statement[0].age_days, 2);
        let f = &r.findings[0];
        assert_eq!(f.severity, Severity::Warn);
        assert!(!f.requires_signoff);
    }

    #[test]
    fn stale_unmatched_statement_is_breach() {
        let r = run(
            vec![st("S1", "2026-08-20", "OLD", 10_000)],
            vec![],
            &config(0), // stale_days 14
        );
        assert!(r.unmatched_statement[0].stale);
        let f = &r.findings[0];
        assert_eq!(f.rule_id, RULE_STMT_UNMATCHED);
        assert_eq!(f.severity, Severity::Breach);
        assert!(f.requires_signoff);
    }

    #[test]
    fn stale_boundary_exactly_at_threshold_is_fresh() {
        // "older than X days" escalates: age == stale_days is not stale.
        let r = run(
            vec![st("S1", "2026-09-08", "EDGE", 10_000)], // exactly 14 days before as_of
            vec![],
            &config(0),
        );
        assert!(!r.unmatched_statement[0].stale);
        assert_eq!(r.findings[0].severity, Severity::Warn);
    }

    #[test]
    fn stale_unmatched_ledger_entry_is_breach() {
        let r = run(
            vec![],
            vec![ld("L1", "2026-08-01", "OLD-LEDG", 30_000)],
            &config(0),
        );
        assert!(r.unmatched_ledger[0].stale);
        let f = &r.findings[0];
        assert_eq!(f.rule_id, RULE_LEDGER_UNMATCHED);
        assert_eq!(f.severity, Severity::Breach);
        assert!(f.requires_signoff);
    }

    // --- proposals ---

    #[test]
    fn adjustment_proposals_cover_both_sides() {
        let r = run(
            vec![st("S1", "2026-09-20", "BANK-ONLY", 10_000)],
            vec![ld("L1", "2026-09-20", "BOOK-ONLY", 30_000)],
            &config(0),
        );
        assert_eq!(r.adjustment_proposals.len(), 2);
        assert_eq!(
            r.adjustment_proposals[0].kind,
            ProposalKind::RecordLedgerEntry
        );
        assert_eq!(r.adjustment_proposals[0].subject, "S1");
        assert_eq!(
            r.adjustment_proposals[1].kind,
            ProposalKind::InvestigateLedgerEntry
        );
        assert_eq!(r.adjustment_proposals[1].subject, "L1");
    }

    // --- pass composition ---

    #[test]
    fn exact_pass_consumes_before_tolerance_pass() {
        // Both ledger lines share the reference; the exact one must win
        // even though the tolerance candidate comes first in input order.
        let r = run(
            vec![st("S1", "2026-09-01", "REF", 100_000)],
            vec![
                ld("L1", "2026-09-01", "REF", 100_010),
                ld("L2", "2026-09-01", "REF", 100_000),
            ],
            &config(100),
        );
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].tier, MatchTier::Exact);
        assert_eq!(r.matches[0].ledger_ids, vec!["L2"]);
    }

    #[test]
    fn cents_format_is_signed_decimal_without_floats() {
        assert_eq!(fmt_cents(125_050), "+1250.50");
        assert_eq!(fmt_cents(-50_005), "-500.05");
        assert_eq!(fmt_cents(0), "+0.00");
    }
}
