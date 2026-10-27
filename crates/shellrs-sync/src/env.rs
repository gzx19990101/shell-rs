//! Time and randomness, the only inputs a round takes from the world
//! besides its arguments: tests and the app's UI tests pass `FixedEnv`, so
//! a round gives the same result every time. Nothing else in the core reads
//! the clock or the system's random source (`no_clock_or_random_elsewhere`).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::SyncError;

pub trait Env: Send {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), SyncError>;
}

/// The system's clock and random source.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemEnv;

impl Env for SystemEnv {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), SyncError> {
        getrandom::fill(out).map_err(|_| SyncError::Random)
    }
}

/// A clock that moves only when told to and random bytes from a seed
/// (SplitMix64): not for keys anyone relies on, only for tests.
#[derive(Clone, Debug)]
pub struct FixedEnv {
    now_ms: u64,
    state: u64,
}

impl FixedEnv {
    pub fn new(now_ms: u64, seed: u64) -> Self {
        Self {
            now_ms,
            state: seed,
        }
    }

    pub fn advance(&mut self, ms: u64) {
        self.now_ms = self.now_ms.saturating_add(ms);
    }

    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// The next number of the sequence.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl Env for FixedEnv {
    fn now_ms(&self) -> u64 {
        self.now_ms
    }

    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), SyncError> {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

pub(crate) fn random_array<const N: usize>(env: &mut dyn Env) -> Result<[u8; N], SyncError> {
    let mut out = [0; N];
    env.fill_random(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_env_repeats_itself() {
        let mut one = FixedEnv::new(5, 42);
        let mut two = FixedEnv::new(5, 42);
        let (mut a, mut b) = ([0u8; 13], [0u8; 13]);
        one.fill_random(&mut a).unwrap();
        two.fill_random(&mut b).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0; 13]);
        one.advance(10);
        assert_eq!(one.now_ms(), 15);
    }

    /// Only this file, the local folder store, which reads file times, and
    /// the S3 store, which signs requests with the time, may touch the
    /// clock or the random source: everything else gets them through
    /// `Env`, so a round is a function of its arguments.
    #[test]
    fn no_clock_or_random_elsewhere() {
        fn visit(dir: &std::path::Path, found: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    visit(&path, found);
                    continue;
                }
                let name = path.to_string_lossy().replace('\\', "/");
                if name.ends_with("src/env.rs")
                    || name.ends_with("src/store/local.rs")
                    || name.ends_with("src/store/s3.rs")
                {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for needle in ["SystemTime", "getrandom", "Instant::now", "thread_rng"] {
                    if text.contains(needle) {
                        found.push(format!("{name}: {needle}"));
                    }
                }
            }
        }
        let mut found = Vec::new();
        visit(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );
        assert!(found.is_empty(), "{found:?}");
    }
}
