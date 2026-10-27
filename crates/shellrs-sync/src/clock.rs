//! Versions: which of two copies of a record is the later.
//!
//! A version is a hybrid logical clock reading, wall milliseconds and a
//! counter, plus the device that wrote it. A device's clock never goes
//! below the newest version it has seen, so whatever it writes after seeing
//! a version sorts after it, however wrong its wall clock; between edits
//! nobody saw each other make, the wall clock decides.

use std::cmp::Ordering;

use crate::DeviceId;

/// A clock reading: milliseconds since the Unix epoch, then a counter for
/// readings within the same millisecond. Written as two JSON numbers, each
/// exact in any JSON reader (a packed 64-bit number would not be).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stamp {
    pub ms: u64,
    pub counter: u32,
}

impl Stamp {
    /// About the year 6429: a reading past it is a corrupt file.
    pub const MAX_MS: u64 = 1 << 47;

    pub fn is_sane(&self) -> bool {
        self.ms <= Self::MAX_MS
    }
}

/// Who wrote a copy of a record and when. Ordered by the reading, then by
/// device id; two copies with the same version should hold the same thing,
/// and when they do not (two devices that share an id) the merge decides by
/// their contents.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Version {
    pub stamp: Stamp,
    pub device: DeviceId,
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.stamp, &self.device).cmp(&(other.stamp, &other.device))
    }
}

/// The reading a repair of a record at `stamp` gets: just after it, so
/// any edit or deletion made after seeing that record, on any device, wins
/// over the repair, while devices making the same repair agree on it.
pub(crate) fn after(stamp: Stamp) -> Stamp {
    match stamp.counter.checked_add(1) {
        Some(counter) => Stamp {
            ms: stamp.ms,
            counter,
        },
        None => Stamp {
            ms: (stamp.ms + 1).min(Stamp::MAX_MS),
            counter: 0,
        },
    }
}

/// A device's clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Hlc {
    last: Stamp,
}

impl Hlc {
    pub(crate) fn new(last: Stamp) -> Self {
        Self { last }
    }

    pub(crate) fn last(&self) -> Stamp {
        self.last
    }

    /// The reading for something happening at wall time `at_ms`: later than
    /// anything this clock has given or seen. Within a millisecond it counts
    /// by two, leaving the step between for repairs (`after`): whatever a
    /// device does once it has seen a version then outranks a repair of it.
    pub(crate) fn tick(&mut self, at_ms: u64) -> Stamp {
        let at = at_ms.min(Stamp::MAX_MS);
        let next = if at > self.last.ms {
            Stamp { ms: at, counter: 0 }
        } else if let Some(counter) = self.last.counter.checked_add(2) {
            Stamp {
                ms: self.last.ms,
                counter,
            }
        } else {
            Stamp {
                ms: (self.last.ms + 1).min(Stamp::MAX_MS),
                counter: 0,
            }
        };
        self.last = next;
        next
    }

    /// Note a reading another device made.
    pub(crate) fn observe(&mut self, stamp: Stamp) {
        if stamp > self.last && stamp.is_sane() {
            self.last = stamp;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wall_clock_leads_when_it_is_ahead() {
        let mut clock = Hlc::default();
        assert_eq!(
            clock.tick(100),
            Stamp {
                ms: 100,
                counter: 0
            }
        );
        assert_eq!(
            clock.tick(200),
            Stamp {
                ms: 200,
                counter: 0
            }
        );
    }

    #[test]
    fn a_wall_clock_behind_only_counts_up() {
        let mut clock = Hlc::new(Stamp {
            ms: 500,
            counter: 3,
        });
        assert_eq!(
            clock.tick(100),
            Stamp {
                ms: 500,
                counter: 5
            }
        );
        assert_eq!(
            clock.tick(500),
            Stamp {
                ms: 500,
                counter: 7
            }
        );
    }

    #[test]
    fn a_full_counter_carries_into_the_milliseconds() {
        let mut clock = Hlc::new(Stamp {
            ms: 7,
            counter: u32::MAX,
        });
        assert_eq!(clock.tick(0), Stamp { ms: 8, counter: 0 });
    }

    #[test]
    fn what_is_seen_moves_the_clock_on() {
        let mut clock = Hlc::new(Stamp { ms: 10, counter: 0 });
        clock.observe(Stamp { ms: 50, counter: 2 });
        assert_eq!(clock.tick(20), Stamp { ms: 50, counter: 4 });
        clock.observe(Stamp { ms: 30, counter: 0 });
        assert_eq!(clock.last(), Stamp { ms: 50, counter: 4 });
        clock.observe(Stamp {
            ms: Stamp::MAX_MS + 1,
            counter: 0,
        });
        assert_eq!(clock.last(), Stamp { ms: 50, counter: 4 });
    }

    #[test]
    fn a_repair_comes_between_a_version_and_what_follows_it() {
        let seen = Stamp { ms: 50, counter: 4 };
        let mut clock = Hlc::new(seen);
        let repair = after(seen);
        assert!(seen < repair && repair < clock.tick(0));
        assert_eq!(
            after(Stamp {
                ms: 9,
                counter: u32::MAX
            }),
            Stamp { ms: 10, counter: 0 }
        );
    }

    #[test]
    fn versions_sort_by_reading_then_device() {
        let a = DeviceId::parse("aaaaaaaaaaaaaaaa").unwrap();
        let b = DeviceId::parse("bbbbbbbbbbbbbbbb").unwrap();
        let at = |ms, device: &DeviceId| Version {
            stamp: Stamp { ms, counter: 0 },
            device: device.clone(),
        };
        assert!(at(1, &b) < at(2, &a));
        assert!(at(2, &a) < at(2, &b));
    }
}
