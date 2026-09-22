//! Deterministic seeded sampling for control testing.
//!
//! Seed derivation (the only randomness in the family, and fully
//! reproducible): seed = SHA-256 over the canonical serde-JSON encoding of
//! `{ "population_id": ..., "period": ... }` in that fixed field order.
//! Each instance's selection rank is `SHA-256(seed || instance_id)`,
//! lowercase hex; instances sort by `(rank, instance_id)` and the first
//! `n` are the sample. Identical inputs always yield the identical sample,
//! independent of the order instances appear in.

use crate::inputs::ControlInstance;
use serde::Serialize;
use sha2::{Digest, Sha256};
use spine::sha256_hex;

#[derive(Serialize)]
struct SeedKey<'a> {
    population_id: &'a str,
    period: &'a str,
}

/// The testing seed for a population: SHA-256 over the canonical JSON of
/// the population id and period.
pub fn testing_seed(population_id: &str, period: &str) -> [u8; 32] {
    let key = SeedKey {
        population_id,
        period,
    };
    let bytes = serde_json::to_vec(&key)
        .expect("SeedKey is a fixed-shape struct; serialization cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Selection rank of one instance under a seed:
/// `SHA-256(seed || instance_id)`, lowercase hex.
pub fn rank_hex(seed: [u8; 32], instance_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(instance_id.as_bytes());
    sha256_hex(&hasher.finalize())
}

/// Deterministically select `n` of `instances`: rank every instance, sort
/// by `(rank, instance_id)`, take the first `n`. Stable under input
/// reordering; ties break on the instance id.
pub fn select_sample(
    instances: &[ControlInstance],
    n: usize,
    seed: [u8; 32],
) -> Vec<&ControlInstance> {
    let mut ranked: Vec<(String, &ControlInstance)> = instances
        .iter()
        .map(|i| (rank_hex(seed, &i.instance_id), i))
        .collect();
    ranked.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.instance_id.cmp(&b.1.instance_id))
    });
    ranked
        .into_iter()
        .take(n)
        .map(|(_, instance)| instance)
        .collect()
}
