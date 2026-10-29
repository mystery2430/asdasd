//! Cross-network **ISP seed pool** (feature C). Opt-in, via the CLI's
//! `--isp <name>` label.
//!
//! DERIVED, never authoritative: it aggregates the *promoted* strategies from
//! every NetKey the user tagged with one ISP name, and — on a fresh network of
//! that ISP — offers them to the grid sweep ahead of the untried grid. It is a
//! [`SeedTier::IspPool`] source, the weakest tier: a cross-network prior, not
//! same-network proof, so it only reorders `Discover` and never skips the Probe.
//! Deleting the file just means a cold start (no learned state is lost — the
//! NetKey profiles remain the authority).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::profile::persist::{atomic_write, sanitize};
use crate::profile::{ScoredStrategy, SeedTier, StrategyQuality};
use crate::strategy::{Strategy, StrategyId};

/// On-disk format version for the ISP pool file. Independent of the discovery
/// profile's `PROFILE_VERSION`.
pub const ISP_POOL_VERSION: u32 = 1;

/// Only seed from a strategy proven on at least this many distinct networks of
/// the ISP — one network is just this session's house strategy re-labelled.
const MIN_NETWORKS: usize = 2;
/// ...and only if its aggregate `successes / trials` clears this.
const MIN_SUCCESS_RATIO: f32 = 0.6;
/// Cap on per-network contributions kept per strategy (newest `last_seen` wins).
const MAX_CONTRIBUTIONS: usize = 20;

/// One network's evidence for one strategy: the summed trial/success counts of
/// every target on that network that promoted this strategy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Contribution {
    pub net_key: String,
    pub trials: u64,
    pub successes: u64,
    pub targets_promoted: u32,
    #[serde(default)]
    pub quality: StrategyQuality,
    /// Unix seconds of the last session that refreshed this contribution.
    pub last_seen: u64,
}

/// One strategy's pooled evidence across networks of the ISP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IspPoolEntry {
    pub strategy: Strategy,
    pub contributions: Vec<Contribution>,
}

impl IspPoolEntry {
    fn networks(&self) -> usize {
        self.contributions.len()
    }
    fn totals(&self) -> (u64, u64, StrategyQuality) {
        let mut q = StrategyQuality::default();
        let (mut t, mut s) = (0u64, 0u64);
        for c in &self.contributions {
            t += c.trials;
            s += c.successes;
            q.merge(&c.quality);
        }
        (t, s, q)
    }
    /// Clears the `MIN_NETWORKS` + `MIN_SUCCESS_RATIO` gate.
    fn is_seed_worthy(&self) -> bool {
        if self.networks() < MIN_NETWORKS {
            return false;
        }
        let (trials, successes, _) = self.totals();
        trials > 0 && (successes as f32 / trials as f32) >= MIN_SUCCESS_RATIO
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IspPool {
    pub version: u32,
    /// The `--isp` label this pool belongs to (echoed for debugging).
    pub isp: String,
    pub entries: Vec<IspPoolEntry>,
}

/// A stable 64-bit FNV-1a over the exact label. Unlike the readable prefix it
/// distinguishes `ISP A`, `ISP_A`, and case changes that Windows filenames would
/// otherwise fold together.
fn label_hash(isp: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in isp.as_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn isp_file_stem(isp: &str) -> String {
    let readable: String = sanitize(isp).chars().take(64).collect();
    format!("{readable}-{hash:016x}", hash = label_hash(isp))
}

impl IspPool {
    pub fn new(isp: &str) -> Self {
        Self {
            version: ISP_POOL_VERSION,
            isp: isp.to_owned(),
            entries: Vec::new(),
        }
    }

    /// `<dir>/isp/<sanitized-isp>-<label-hash>.json`.
    ///
    /// The human-readable prefix keeps the file browsable, while the stable
    /// hash of the *exact* label makes `ISP A` and `ISP_A` distinct. A lossy
    /// sanitizer alone would map both to `ISP_A`.
    pub fn path(dir: &Path, isp: &str) -> PathBuf {
        dir.join("isp").join(format!("{}.json", isp_file_stem(isp)))
    }

    /// Pre-hash path used before collision-resistant names were added. It is
    /// read-only compatibility: a legacy file is accepted only when its inner
    /// `isp` field matches the requested label exactly.
    fn legacy_path(dir: &Path, isp: &str) -> PathBuf {
        dir.join("isp").join(format!("{}.json", sanitize(isp)))
    }

    /// Read the pool for `isp`. `None` if it does not exist, cannot be parsed,
    /// is a version we do not understand, or belongs to a different ISP label
    /// (all treated as "start cold"). A mismatched legacy file is never merged
    /// into another label's pool.
    pub fn load(dir: &Path, isp: &str) -> Option<Self> {
        let current = Self::path(dir, isp);
        let legacy = Self::legacy_path(dir, isp);
        for path in [current, legacy] {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            match serde_json::from_slice::<IspPool>(&bytes) {
                Ok(p) if p.version == ISP_POOL_VERSION && p.isp == isp => return Some(p),
                Ok(p) => {
                    tracing::warn!(
                        target: "bosphorus::profile",
                        path = %path.display(),
                        expected = %isp,
                        found = %p.isp,
                        "ignoring an ISP pool whose label does not match its filename"
                    );
                    return None;
                }
                Err(_) => return None,
            }
        }
        None
    }

    /// Atomic write (per-process staging file + last-writer-wins rename — see
    /// [`atomic_write`]). Returns the JSON byte count.
    pub fn save(&self, dir: &Path) -> std::io::Result<usize> {
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        atomic_write(&Self::path(dir, &self.isp), &json)?;
        Ok(json.len())
    }

    /// Fold this session's promoted strategies into the pool as `net_key`'s
    /// contribution. Idempotent per network: re-running on the same NetKey
    /// *replaces* its contribution rather than adding a second one, so
    /// `networks` never inflates. `promoted` is `(id, its score)` for every
    /// `Active`-with-strategy target — see [`Discovery::promoted_for_isp`].
    ///
    /// Replace this network's contribution to the pool with `promoted`.
    ///
    /// A contribution is a *snapshot of what this network currently promotes*,
    /// not an append-only log: a strategy that stopped being promoted on this
    /// network must stop contributing evidence, otherwise a strategy that once
    /// worked here keeps counting towards [`Self::seeds`] (and towards
    /// `MIN_NETWORKS`) long after the censor or the network moved on.
    ///
    /// So the merge is structured as: strip every contribution from `net_key`
    /// across the whole pool, insert the new snapshot, then drop entries left
    /// with no contributions at all. Contributions from *other* networks are
    /// untouched, and the per-strategy cap plus ranking rules are unchanged.
    pub fn merge_session(
        &mut self,
        net_key: &str,
        promoted: &[(StrategyId, ScoredStrategy)],
        now_unix: u64,
    ) {
        // 1. Forget what this network said last time. Doing this first (rather
        //    than only for the ids in this snapshot) is what makes a strategy
        //    that is no longer promoted stop contributing.
        for entry in &mut self.entries {
            entry.contributions.retain(|c| c.net_key != net_key);
        }

        // 2. Group this session's promotions by strategy id.
        let mut by_id: HashMap<StrategyId, (Strategy, u64, u64, u32, StrategyQuality)> =
            HashMap::new();
        for (id, sc) in promoted {
            let e = by_id
                .entry(*id)
                .or_insert_with(|| (sc.strategy.clone(), 0, 0, 0, StrategyQuality::default()));
            e.1 += sc.trials as u64;
            e.2 += sc.successes as u64;
            e.3 += 1;
            e.4.merge(&sc.quality);
        }

        for (id, (strategy, trials, successes, targets, quality)) in by_id {
            let contrib = Contribution {
                net_key: net_key.to_owned(),
                trials,
                successes,
                targets_promoted: targets,
                quality,
                last_seen: now_unix,
            };
            let entry = match self.entries.iter_mut().find(|e| e.strategy.id() == id) {
                Some(e) => e,
                None => {
                    self.entries.push(IspPoolEntry {
                        strategy,
                        contributions: Vec::new(),
                    });
                    self.entries.last_mut().unwrap()
                }
            };
            // `net_key` was removed from every entry above, so this is the
            // network's only contribution.
            debug_assert!(!entry.contributions.iter().any(|c| c.net_key == net_key));
            entry.contributions.push(contrib);
            if entry.contributions.len() > MAX_CONTRIBUTIONS {
                entry
                    .contributions
                    .sort_by_key(|c| std::cmp::Reverse(c.last_seen));
                entry.contributions.truncate(MAX_CONTRIBUTIONS);
            }
        }

        // 3. A strategy with no evidence left from any network is not evidence.
        self.entries.retain(|e| !e.contributions.is_empty());
    }

    /// The seed list this pool contributes to a fresh `Discover` target: every
    /// entry that clears the corroboration gate, most-proven first
    /// (`networks` desc, then retransmit-free-looking, then lowest latency).
    /// All tagged [`SeedTier::IspPool`].
    pub fn seeds(&self) -> Vec<(StrategyId, SeedTier)> {
        let mut ranked: Vec<(&IspPoolEntry, usize, StrategyQuality)> = self
            .entries
            .iter()
            .filter(|e| e.is_seed_worthy())
            .map(|e| {
                let (_, _, q) = e.totals();
                (e, e.networks(), q)
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.looks_fast().cmp(&a.2.looks_fast()))
                .then_with(|| match (a.2.min_latency, b.2.min_latency) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                })
        });
        ranked
            .into_iter()
            .map(|(e, ..)| (e.strategy.id(), SeedTier::IspPool))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EvasionConfig;
    use crate::strategy::DefaultGenerator;

    fn gen() -> DefaultGenerator {
        DefaultGenerator::new(&EvasionConfig::default())
    }
    fn score(strategy: Strategy, trials: u32, successes: u32) -> ScoredStrategy {
        let mut s = ScoredStrategy::new(strategy);
        s.trials = trials;
        s.successes = successes;
        s
    }

    #[test]
    fn merge_is_idempotent_for_one_network() {
        let g = gen();
        let s0 = g.all()[0].clone();
        let mut pool = IspPool::new("acme");
        pool.merge_session("netA", &[(s0.id(), score(s0.clone(), 3, 2))], 100);
        pool.merge_session("netA", &[(s0.id(), score(s0.clone(), 9, 8))], 200);
        assert_eq!(pool.entries.len(), 1);
        assert_eq!(
            pool.entries[0].contributions.len(),
            1,
            "same network -> one contribution"
        );
        // The later run's counts replaced the earlier ones.
        let (t, s, _) = pool.entries[0].totals();
        assert_eq!((t, s), (9, 8));
    }

    #[test]
    fn seeds_need_two_networks_and_a_passing_ratio() {
        let g = gen();
        let (a, b, c) = (g.all()[0].clone(), g.all()[1].clone(), g.all()[2].clone());
        let mut pool = IspPool::new("acme");

        // a: only one network -> excluded no matter how good.
        pool.merge_session("net1", &[(a.id(), score(a.clone(), 10, 10))], 1);
        // b: two networks but ratio 4/10 = 0.4 -> excluded.
        pool.merge_session("net1", &[(b.id(), score(b.clone(), 5, 2))], 1);
        pool.merge_session("net2", &[(b.id(), score(b.clone(), 5, 2))], 1);
        // c: two networks, ratio 7/10 = 0.7 -> included.
        pool.merge_session("net1", &[(c.id(), score(c.clone(), 5, 4))], 1);
        pool.merge_session("net2", &[(c.id(), score(c.clone(), 5, 3))], 1);

        let seeds = pool.seeds();
        assert_eq!(seeds, vec![(c.id(), SeedTier::IspPool)]);
    }

    #[test]
    fn seeds_are_ordered_by_network_count_desc() {
        let g = gen();
        let (a, b) = (g.all()[0].clone(), g.all()[1].clone());
        let mut pool = IspPool::new("acme");
        // b on 3 networks, a on 2 — both pass the ratio gate. Each call is one
        // network's *complete* promoted set, so both strategies go in the same
        // snapshot for a shared network.
        for n in ["n1", "n2"] {
            pool.merge_session(
                n,
                &[
                    (a.id(), score(a.clone(), 4, 3)),
                    (b.id(), score(b.clone(), 4, 3)),
                ],
                1,
            );
        }
        pool.merge_session("n3", &[(b.id(), score(b.clone(), 4, 3))], 1);
        assert_eq!(
            pool.seeds(),
            vec![(b.id(), SeedTier::IspPool), (a.id(), SeedTier::IspPool)],
            "more networks first"
        );
    }

    #[test]
    fn contributions_are_capped_to_the_newest() {
        let g = gen();
        let a = g.all()[0].clone();
        let mut pool = IspPool::new("acme");
        for i in 0..(MAX_CONTRIBUTIONS as u64 + 5) {
            pool.merge_session(&format!("net{i}"), &[(a.id(), score(a.clone(), 2, 2))], i);
        }
        assert_eq!(pool.entries[0].contributions.len(), MAX_CONTRIBUTIONS);
        let oldest = pool.entries[0]
            .contributions
            .iter()
            .map(|c| c.last_seen)
            .min()
            .unwrap();
        assert_eq!(oldest, 5, "the 5 oldest contributions were dropped");
    }

    #[test]
    fn save_load_round_trips_and_leaves_no_temp() {
        let g = gen();
        let a = g.all()[0].clone();
        let dir = tempfile::tempdir().unwrap();
        let mut pool = IspPool::new("Acme ISP / Fibre");
        pool.merge_session("n1", &[(a.id(), score(a.clone(), 4, 3))], 1);
        pool.merge_session("n2", &[(a.id(), score(a.clone(), 4, 3))], 2);
        pool.save(dir.path()).unwrap();

        let back = IspPool::load(dir.path(), "Acme ISP / Fibre").unwrap();
        assert_eq!(back.version, ISP_POOL_VERSION);
        assert_eq!(back.seeds(), vec![(a.id(), SeedTier::IspPool)]);
        let isp_dir = dir.path().join("isp");
        let tmps: Vec<_> = std::fs::read_dir(&isp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(tmps.is_empty(), "left a temp file: {tmps:?}");
    }

    #[test]
    fn colliding_sanitized_labels_get_distinct_files_and_stay_separate() {
        let dir = tempfile::tempdir().unwrap();
        let g = gen();
        let a = g.all()[0].clone();
        let b = g.all()[1].clone();
        assert_eq!(sanitize("ISP A"), sanitize("ISP_A"));
        assert_ne!(
            IspPool::path(dir.path(), "ISP A"),
            IspPool::path(dir.path(), "ISP_A")
        );

        let mut spaced = IspPool::new("ISP A");
        spaced.merge_session("netA", &[(a.id(), score(a.clone(), 4, 3))], 1);
        spaced.save(dir.path()).unwrap();
        let mut underscored = IspPool::new("ISP_A");
        underscored.merge_session("netB", &[(b.id(), score(b.clone(), 4, 3))], 2);
        underscored.save(dir.path()).unwrap();

        let spaced_back = IspPool::load(dir.path(), "ISP A").unwrap();
        let underscored_back = IspPool::load(dir.path(), "ISP_A").unwrap();
        assert_eq!(spaced_back.isp, "ISP A");
        assert_eq!(underscored_back.isp, "ISP_A");
        assert_eq!(spaced_back.entries.len(), 1);
        assert_eq!(underscored_back.entries.len(), 1);
        assert_eq!(spaced_back.entries[0].strategy.id(), a.id());
        assert_eq!(underscored_back.entries[0].strategy.id(), b.id());
    }

    #[test]
    fn load_rejects_a_pool_whose_inner_label_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let wrong = IspPool::new("other-isp");
        wrong.save(dir.path()).unwrap();
        // Put the wrong-label payload at the requested label's path as well as
        // the legacy path; neither may be adopted.
        let requested = IspPool::path(dir.path(), "wanted");
        std::fs::create_dir_all(requested.parent().unwrap()).unwrap();
        std::fs::copy(IspPool::path(dir.path(), "other-isp"), &requested).unwrap();
        assert!(IspPool::load(dir.path(), "wanted").is_none());

        let mut mismatched = IspPool::new("wanted");
        mismatched.isp = "other-isp".to_string();
        std::fs::write(&requested, serde_json::to_vec_pretty(&mismatched).unwrap()).unwrap();
        assert!(IspPool::load(dir.path(), "wanted").is_none());
    }

    #[test]
    fn a_legacy_file_is_read_only_when_its_inner_label_matches() {
        let dir = tempfile::tempdir().unwrap();
        let pool = IspPool::new("Acme ISP / Fibre");
        let legacy = dir
            .path()
            .join("isp")
            .join(format!("{}.json", sanitize("Acme ISP / Fibre")));
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, serde_json::to_vec_pretty(&pool).unwrap()).unwrap();
        assert!(IspPool::load(dir.path(), "Acme ISP / Fibre").is_some());

        let mut wrong = IspPool::new("Acme ISP / Fibre");
        wrong.isp = "somebody else".to_string();
        std::fs::write(&legacy, serde_json::to_vec_pretty(&wrong).unwrap()).unwrap();
        assert!(IspPool::load(dir.path(), "Acme ISP / Fibre").is_none());
    }

    #[test]
    fn load_rejects_an_unknown_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = IspPool::path(dir.path(), "acme");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, br#"{"version":999,"isp":"acme","entries":[]}"#).unwrap();
        assert!(IspPool::load(dir.path(), "acme").is_none());
    }

    #[test]
    fn isp_pool_tier_is_weak_default_threshold_and_never_skips_the_probe() {
        assert_eq!(
            SeedTier::IspPool.promote_threshold(2),
            2,
            "no 1-success shortcut"
        );
        assert!(
            !SeedTier::IspPool.is_high_confidence(),
            "must not trigger Probe-skip"
        );
    }

    /// Regression: `merge_session` only replaced this network's contribution for
    /// strategies present in the new snapshot. A strategy that dropped out of the
    /// snapshot kept its old contribution from this network, so it could still
    /// count as corroborated and keep being seeded.
    #[test]
    fn a_strategy_dropped_by_the_same_network_stops_contributing() {
        let g = gen();
        let (a, b) = (g.all()[0].clone(), g.all()[1].clone());
        let mut pool = IspPool::new("acme");

        // net1 promotes both.
        pool.merge_session(
            "net1",
            &[
                (a.id(), score(a.clone(), 4, 4)),
                (b.id(), score(b.clone(), 4, 4)),
            ],
            100,
        );
        assert_eq!(pool.entries.len(), 2);

        // net1's *next* session promotes only a. b's net1 evidence must be
        // withdrawn; before the fix it stayed and kept b corroborated.
        pool.merge_session("net1", &[(a.id(), score(a.clone(), 4, 4))], 200);

        assert!(
            !pool.entries.iter().any(|e| e.strategy.id() == b.id()),
            "b had evidence only from net1, so withdrawing it removes the entry"
        );
        assert_eq!(
            pool.entries
                .iter()
                .find(|e| e.strategy.id() == a.id())
                .map(|e| e.contributions.len()),
            Some(1),
            "a keeps exactly its refreshed net1 contribution"
        );
        assert!(
            !pool.seeds().iter().any(|(id, _)| *id == b.id()),
            "a strategy with no remaining evidence must not be seeded"
        );

        // Now net2 corroborates a: a is a real cross-network seed.
        pool.merge_session("net2", &[(a.id(), score(a.clone(), 4, 4))], 300);
        assert_eq!(pool.seeds(), vec![(a.id(), SeedTier::IspPool)]);
        assert!(
            !pool.entries.iter().any(|e| e.strategy.id() == b.id()),
            "b is still gone"
        );
    }

    /// An empty snapshot means "this network promotes nothing now", so it must
    /// withdraw its evidence rather than leave the old numbers behind.
    #[test]
    fn an_empty_snapshot_withdraws_that_networks_evidence() {
        let g = gen();
        let a = g.all()[0].clone();
        let mut pool = IspPool::new("acme");
        pool.merge_session("net1", &[(a.id(), score(a.clone(), 5, 5))], 100);
        pool.merge_session("net2", &[(a.id(), score(a.clone(), 5, 5))], 100);
        assert_eq!(pool.seeds(), vec![(a.id(), SeedTier::IspPool)]);

        pool.merge_session("net2", &[], 200);
        assert!(
            pool.seeds().is_empty(),
            "one network is not corroboration, so nothing may be seeded"
        );
        assert_eq!(pool.entries.len(), 1);
        assert_eq!(pool.entries[0].contributions.len(), 1);
        assert_eq!(pool.entries[0].contributions[0].net_key, "net1");

        // Withdrawing the last network removes the entry entirely.
        pool.merge_session("net1", &[], 300);
        assert!(pool.entries.is_empty(), "no contributions -> no entry");
        assert!(pool.seeds().is_empty());
    }

    /// Other networks' evidence must survive one network withdrawing.
    #[test]
    fn withdrawing_one_network_preserves_the_others() {
        let g = gen();
        let a = g.all()[0].clone();
        let mut pool = IspPool::new("acme");
        for (i, n) in ["net1", "net2", "net3"].iter().enumerate() {
            pool.merge_session(n, &[(a.id(), score(a.clone(), 3, 3))], 10 + i as u64);
        }
        assert_eq!(pool.entries[0].contributions.len(), 3);

        pool.merge_session("net1", &[], 400);
        let keys: Vec<&str> = pool.entries[0]
            .contributions
            .iter()
            .map(|c| c.net_key.as_str())
            .collect();
        assert_eq!(keys, vec!["net2", "net3"], "net1 gone, net2/net3 kept");
        assert_eq!(
            pool.entries[0].contributions[0].last_seen, 11,
            "the surviving evidence is unchanged"
        );
        assert_eq!(pool.entries[0].contributions[1].last_seen, 12);
        assert_eq!(pool.entries[0].networks(), 2);
        // Still seed-worthy: two networks remain.
        assert_eq!(pool.seeds(), vec![(a.id(), SeedTier::IspPool)]);
    }

    /// The per-network cap keeps working after the rewrite (a re-promoted
    /// strategy replaces its own contribution instead of adding a second one).
    #[test]
    fn repeated_promotion_across_networks_still_caps_contributions() {
        let g = gen();
        let a = g.all()[0].clone();
        let mut pool = IspPool::new("acme");
        for i in 0..(MAX_CONTRIBUTIONS as u64 + 3) {
            pool.merge_session(&format!("net{i}"), &[(a.id(), score(a.clone(), 2, 2))], i);
        }
        assert_eq!(pool.entries.len(), 1);
        assert_eq!(pool.entries[0].contributions.len(), MAX_CONTRIBUTIONS);
        // Re-promoting an existing network must not grow the list.
        pool.merge_session("net30", &[(a.id(), score(a.clone(), 2, 2))], 999);
        assert_eq!(pool.entries[0].contributions.len(), MAX_CONTRIBUTIONS);
        assert!(pool.entries[0]
            .contributions
            .iter()
            .any(|c| c.net_key == "net30" && c.last_seen == 999));
    }
}
