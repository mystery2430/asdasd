//! Minimal JSON persistence for discovery profiles (M8).
//!
//! One file per network fingerprint (`<dir>/<net_key>.json`). Holds the
//! per-target sweep state so multiple short sessions accumulate toward the full
//! grid instead of restarting from `Probe` every process launch.
//!
//! Compatibility: on load, every persisted `StrategyId` is checked against the
//! live grid. If they are all still present the target is fully restored (and
//! [`grid_size_at_exhaustion`](crate::profile::TargetState::grid_size_at_exhaustion)
//! lets an `Exhausted` target revive under a grown grid). If any id is gone
//! (the grid was renumbered), the per-strategy data is dropped and only the
//! learned server TTL is kept.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::profile::{NetPhase, StrategyQuality};
use crate::strategy::{Strategy, StrategyId};

/// On-disk format version. Bump on an incompatible schema change.
///
/// Still `1` after adding [`PersistedScore::quality`]: the new field is
/// `#[serde(default)]`, so a v1 file written before that change loads fine and
/// the quality counters simply start from zero. Also still `1` after dropping
/// `PersistedTarget::consecutive_success`: deserialization ignores unknown keys,
/// so an older file that still carries it loads without complaint (the value is
/// discarded — the success streak is now per-candidate and not persisted).
pub const PROFILE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedScore {
    pub strategy: Strategy,
    pub trials: u32,
    pub successes: u32,
    /// Latency / retransmit quality. Absent in profiles written before it
    /// existed — defaults to empty.
    #[serde(default)]
    pub quality: StrategyQuality,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedTarget {
    pub key: String,
    pub phase: NetPhase,
    pub tried: Vec<StrategyId>,
    pub scores: Vec<PersistedScore>,
    pub active: Option<StrategyId>,
    pub consecutive_failure: u8,
    pub server_initial_ttl: Option<u8>,
    /// Absent in profiles written before this existed — defaults to `None`.
    #[serde(default)]
    pub injector_hops: Option<u8>,
    pub grid_size_at_exhaustion: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileFile {
    pub version: u32,
    /// FNV-1a over every current grid `StrategyId` (informational — the actual
    /// keep/drop decision is a per-id subset check).
    pub grid_signature: u64,
    /// The NetKey this file is stored under (echoed for debugging).
    pub net_key: String,
    pub targets: Vec<PersistedTarget>,
}

impl ProfileFile {
    pub fn new(grid_signature: u64, net_key: &str, targets: Vec<PersistedTarget>) -> Self {
        Self {
            version: PROFILE_VERSION,
            grid_signature,
            net_key: net_key.to_owned(),
            targets,
        }
    }
}

pub(crate) fn sanitize(net_key: &str) -> String {
    net_key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn profile_path(dir: &Path, net_key: &str) -> PathBuf {
    dir.join(format!("{}.json", sanitize(net_key)))
}

/// One lock stripe per target path. The process id used to be the only
/// disambiguator, so the periodic writer and the shutdown writer in one process
/// staged through the same file. Writes are now unique per call *and*
/// serialized per target, so two threads cannot interleave a temp/rename pair.
static WRITE_LOCKS: [Mutex<()>; 64] = [const { Mutex::new(()) }; 64];
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn write_lock(path: &Path) -> &'static Mutex<()> {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    &WRITE_LOCKS[(hasher.finish() as usize) % WRITE_LOCKS.len()]
}

fn unique_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!(
        "{}.{}.{}",
        std::process::id(),
        nanos,
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )
}

/// Highest snapshot sequence committed per profile path in this process.
///
/// A profile writer exports a snapshot, then serializes and renames it. Without
/// an ordering guard a slow writer holding an *older* snapshot can land after a
/// newer one and silently roll the profile back. Every write therefore carries a
/// sequence assigned before the snapshot is taken, and a write is skipped when a
/// higher sequence has already been committed for that path. The last bytes on
/// disk are always those of the newest snapshot this process produced.
static LAST_COMMITTED: Mutex<Vec<(PathBuf, u64)>> = Mutex::new(Vec::new());

/// Process-wide snapshot counter. Export age must be ordered across *every*
/// writer in the process, not per [`Engine`](crate::Engine): two engines pointed
/// at one profile directory would otherwise both start at 1 and the second one's
/// snapshot would look stale against the first one's already-committed sequence
/// and be dropped.
static NEXT_SNAPSHOT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Take the next snapshot sequence number.
///
/// Call this **before** exporting the snapshot it describes: the value records
/// how old the contents are, not when the write happened.
pub fn next_snapshot_seq() -> u64 {
    NEXT_SNAPSHOT_SEQ.fetch_add(1, Ordering::SeqCst) + 1
}

/// Write `bytes` to `path` atomically: a unique staging file, then a
/// last-writer-wins rename. The target is never left torn, concurrent writers in
/// one process cannot share a temp, and a failed write removes its staging file.
/// Shared by the discovery profile and the ISP seed pool.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_write_with_tag(path, bytes, &unique_tag())
}

fn atomic_write_with_tag(path: &Path, bytes: &[u8], tag: &str) -> io::Result<()> {
    let _guard = write_lock(path).lock();
    stage_and_rename(path, bytes, tag)
}

/// Stage + rename without taking [`write_lock`]; callers that already hold it
/// (or need the lock across serialization) use this directly.
fn stage_and_rename(path: &Path, bytes: &[u8], tag: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("json");
    let tmp = path.with_extension(format!("{ext}.{tag}.tmp"));
    if let Err(e) = std::fs::write(&tmp, bytes) {
        // A partial staging file is never useful; do not leak it.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Versioned atomic write: commit `file` only if `seq` is newer than the last
/// snapshot committed for this path.
///
/// `seq` must be assigned *before* the snapshot is exported, and must increase
/// per writer. Returns `Ok(None)` when the write was discarded because a newer
/// snapshot is already on disk. Serialization happens under the per-path lock so
/// two writers cannot interleave a stale export with a fresh rename.
pub fn save_snapshot(
    dir: &Path,
    net_key: &str,
    file: &ProfileFile,
    seq: u64,
) -> io::Result<Option<usize>> {
    let path = profile_path(dir, net_key);
    let _guard = write_lock(&path).lock();

    let mut committed = LAST_COMMITTED.lock();
    if committed
        .iter()
        .any(|(seen_path, seen_seq)| seen_path == &path && *seen_seq >= seq)
    {
        return Ok(None);
    }
    let json = serde_json::to_vec_pretty(file).map_err(io::Error::other)?;
    stage_and_rename(&path, &json, &unique_tag())?;
    match committed
        .iter_mut()
        .find(|(seen_path, _)| seen_path == &path)
    {
        Some(entry) => entry.1 = seq,
        None => committed.push((path, seq)),
    }
    Ok(Some(json.len()))
}

/// Read `<dir>/<net_key>.json`. `None` if it does not exist or cannot be
/// parsed (a corrupt file is treated as "start fresh").
pub fn load(dir: &Path, net_key: &str) -> Option<ProfileFile> {
    let bytes = std::fs::read(profile_path(dir, net_key)).ok()?;
    match serde_json::from_slice::<ProfileFile>(&bytes) {
        Ok(f) if f.version == PROFILE_VERSION => Some(f),
        _ => None,
    }
}

/// Atomic write (see [`atomic_write`]): a per-process staging file then a
/// last-writer-wins rename. Two processes pointed at the same store — the
/// service and an interactive `--engine` sharing `%ProgramData%` — never write
/// the same temp and never leave the target torn, but one can overwrite the
/// other's incremental learning. The profile is a cache, not a ledger — the next
/// session re-learns — so this is acceptable; callers just should not run both
/// against one store for long stretches. Returns the JSON byte count.
pub fn save(dir: &Path, net_key: &str, file: &ProfileFile) -> io::Result<usize> {
    let json = serde_json::to_vec_pretty(file).map_err(io::Error::other)?;
    atomic_write(&profile_path(dir, net_key), &json)?;
    Ok(json.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::Strategy;

    fn sample() -> ProfileFile {
        ProfileFile::new(
            0xdead_beef,
            "gw=192.168.1.1;net=192.168.1.0/24;dns=lan",
            vec![PersistedTarget {
                key: "updates.discord.com".into(),
                phase: NetPhase::Discover,
                tried: vec![Strategy::m4_fixed().id()],
                scores: vec![PersistedScore {
                    strategy: Strategy::m4_fixed(),
                    trials: 3,
                    successes: 0,
                    quality: StrategyQuality::default(),
                }],
                active: None,
                consecutive_failure: 1,
                server_initial_ttl: Some(128),
                injector_hops: Some(4),
                grid_size_at_exhaustion: None,
            }],
        )
    }

    #[test]
    fn json_round_trips() {
        let f = sample();
        let j = serde_json::to_string(&f).unwrap();
        let back: ProfileFile = serde_json::from_str(&j).unwrap();
        assert_eq!(back.version, PROFILE_VERSION);
        assert_eq!(back.targets.len(), 1);
        assert_eq!(back.targets[0].key, "updates.discord.com");
        assert_eq!(back.targets[0].tried, f.targets[0].tried);
    }

    #[test]
    fn save_then_load_reproduces_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = "abc123";
        assert!(load(dir.path(), key).is_none());

        save(dir.path(), key, &sample()).unwrap();
        let back = load(dir.path(), key).unwrap();
        assert_eq!(back.targets[0].server_initial_ttl, Some(128));
        assert_eq!(back.targets[0].injector_hops, Some(4));
        assert_eq!(back.grid_signature, 0xdead_beef);
        // No stray temp file left behind.
        assert!(
            !tmp_files(dir.path()).iter().any(|_| true),
            "left a .tmp file"
        );
    }

    #[test]
    fn missing_injector_hops_field_defaults_to_none() {
        // A target JSON written before `injector_hops` existed, e.g. from an
        // older build. #[serde(default)] must let it load, not just skip it.
        let json = r#"{
            "key": "example.com",
            "phase": "Discover",
            "tried": [],
            "scores": [],
            "active": null,
            "consecutive_failure": 0,
            "server_initial_ttl": null,
            "grid_size_at_exhaustion": null
        }"#;
        let pt: PersistedTarget =
            serde_json::from_str(json).expect("old-format target still loads");
        assert_eq!(pt.injector_hops, None);
    }

    #[test]
    fn corrupt_file_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(profile_path(dir.path(), "k"), b"{ not json").unwrap();
        assert!(load(dir.path(), "k").is_none());
    }

    fn tmp_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn a_second_writers_save_does_not_disturb_the_first_writers_staged_temp() {
        // Two processes share one store. Writer P1 has staged its temp but not
        // yet renamed; writer P2 runs a full save meanwhile. Per-process temp
        // names mean P2 cannot touch P1's staging file, and P2's own write lands
        // as a valid store.
        let dir = tempfile::tempdir().unwrap();
        let key = "net";
        let path = profile_path(dir.path(), key);
        let p1_tmp = path.with_extension("json.p1.tmp");
        std::fs::write(&p1_tmp, b"P1-STAGED-BYTES").unwrap();

        let json = serde_json::to_vec_pretty(&sample()).unwrap();
        atomic_write_with_tag(&path, &json, "p2").unwrap();

        assert_eq!(
            std::fs::read(&p1_tmp).unwrap(),
            b"P1-STAGED-BYTES",
            "P1's temp was clobbered"
        );
        assert!(
            load(dir.path(), key).is_some(),
            "P2's save produced a valid store"
        );
        // P2 cleaned up after itself; only P1's staging file remains.
        assert_eq!(tmp_files(dir.path()), vec!["net.json.p1.tmp".to_string()]);
    }

    #[test]
    fn concurrent_saves_to_one_profile_always_leave_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let key = "net";
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let dir = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    for n in 0..25 {
                        let mut file = sample();
                        file.targets[0].key = format!("writer-{i}-{n}.example");
                        save(&dir, key, &file).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        let back = load(dir.path(), key).expect("the final file must be valid JSON");
        assert_eq!(back.version, PROFILE_VERSION);
        assert_eq!(back.targets.len(), 1);
        assert!(back.targets[0].key.starts_with("writer-"));
        assert!(
            tmp_files(dir.path()).is_empty(),
            "temp litter: {:?}",
            tmp_files(dir.path())
        );
    }

    #[test]
    fn a_failed_rename_removes_the_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        // Renaming a file over an existing directory fails; the temp must not
        // survive a failed save.
        let target = dir.path().join("profile.json");
        std::fs::create_dir(&target).unwrap();
        assert!(atomic_write(&target, b"{\"version\":1}").is_err());
        let leftovers = tmp_files(dir.path());
        assert!(leftovers.is_empty(), "staging file leaked: {leftovers:?}");
    }

    #[test]
    fn back_to_back_saves_to_one_store_leave_a_valid_file_last_writer_wins() {
        let dir = tempfile::tempdir().unwrap();
        let key = "net";
        let path = profile_path(dir.path(), key);
        let mut a = sample();
        a.targets[0].key = "a.example".into();
        let mut b = sample();
        b.targets[0].key = "b.example".into();

        atomic_write_with_tag(&path, &serde_json::to_vec_pretty(&a).unwrap(), "1111").unwrap();
        atomic_write_with_tag(&path, &serde_json::to_vec_pretty(&b).unwrap(), "2222").unwrap();

        let back = load(dir.path(), key).unwrap();
        assert_eq!(back.targets.len(), 1);
        assert_eq!(back.targets[0].key, "b.example", "last writer wins");
        assert!(tmp_files(dir.path()).is_empty(), "no temp litter");
    }

    #[test]
    fn a_stale_snapshot_cannot_overwrite_a_newer_one() {
        // Regression: the periodic tick thread and the shutdown flush both write
        // the profile. A worker that exported its snapshot first must not land
        // last and roll the file back.
        let dir = tempfile::tempdir().unwrap();
        let key = "net";

        let mut fresh = sample();
        fresh.targets[0].key = "fresh.example".into();
        fresh.targets[0].consecutive_failure = 7;
        assert_eq!(
            save_snapshot(dir.path(), key, &fresh, 2).unwrap(),
            Some(serde_json::to_vec_pretty(&fresh).unwrap().len())
        );

        let mut stale = sample();
        stale.targets[0].key = "stale.example".into();
        stale.targets[0].consecutive_failure = 1;
        assert!(
            save_snapshot(dir.path(), key, &stale, 1).unwrap().is_none(),
            "an older snapshot must be discarded"
        );

        let back = load(dir.path(), key).unwrap();
        assert_eq!(back.targets[0].key, "fresh.example");
        assert_eq!(back.targets[0].consecutive_failure, 7);
        assert!(tmp_files(dir.path()).is_empty());
    }

    #[test]
    fn out_of_order_writers_always_leave_the_highest_snapshot() {
        // Many writers race; completion order is arbitrary. Whatever the order,
        // the file must end on the highest sequence, which is the newest state.
        let dir = tempfile::tempdir().unwrap();
        let key = "net";
        let mut handles = Vec::new();
        for seq in 1u64..=32 {
            let dir = dir.path().to_path_buf();
            handles.push(std::thread::spawn(move || {
                let mut file = sample();
                file.targets[0].key = format!("writer-{seq}.example");
                file.targets[0].consecutive_failure = seq as u8;
                save_snapshot(&dir, key, &file, seq).unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let back = load(dir.path(), key).expect("final file is valid JSON");
        assert_eq!(back.targets[0].key, "writer-32.example");
        assert_eq!(back.targets[0].consecutive_failure, 32);
        assert!(tmp_files(dir.path()).is_empty());
    }

    #[test]
    fn an_equal_sequence_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let key = "net";
        let mut first = sample();
        first.targets[0].key = "first.example".into();
        assert!(save_snapshot(dir.path(), key, &first, 5).unwrap().is_some());

        let mut second = sample();
        second.targets[0].key = "second.example".into();
        assert!(save_snapshot(dir.path(), key, &second, 5)
            .unwrap()
            .is_none());
        assert_eq!(
            load(dir.path(), key).unwrap().targets[0].key,
            "first.example"
        );
    }

    #[test]
    fn the_snapshot_sequence_is_process_wide() {
        // Regression: the counter used to live on `Engine`. A second engine in the
        // same process targeting the same profile path started again at 1, so its
        // first write looked older than the first engine's committed snapshot and
        // was silently discarded (its learned state never reached disk).
        let dir = tempfile::tempdir().unwrap();
        let key = "shared";

        let mut older = sample();
        older.targets[0].key = "engine-a.example".into();
        let seq_a = next_snapshot_seq();
        assert!(save_snapshot(dir.path(), key, &older, seq_a)
            .unwrap()
            .is_some());

        let mut newer = sample();
        newer.targets[0].key = "engine-b.example".into();
        let seq_b = next_snapshot_seq();
        assert!(seq_b > seq_a, "the counter must not restart per writer");
        assert!(
            save_snapshot(dir.path(), key, &newer, seq_b)
                .unwrap()
                .is_some(),
            "the newer writer's snapshot must be committed"
        );

        assert_eq!(
            load(dir.path(), key).unwrap().targets[0].key,
            "engine-b.example"
        );

        // The mechanism the regression caught: a counter that restarts per
        // writer hands out a sequence that is not newer than what is already
        // committed, and the guard then throws the *newer* state away.
        let mut restarted = sample();
        restarted.targets[0].key = "engine-b-again.example".into();
        assert!(
            save_snapshot(dir.path(), key, &restarted, 1).unwrap().is_none(),
            "a restarted counter must be rejected, not silently overwrite newer state"
        );
        assert_eq!(
            load(dir.path(), key).unwrap().targets[0].key,
            "engine-b.example",
            "the guard kept the newest snapshot"
        );
        assert!(tmp_files(dir.path()).is_empty());
    }
}
