//! Merging copies: per record, the greatest version wins.
//!
//! The result does not depend on the order copies come in, how they are
//! grouped, or how often one comes again, so devices that have seen the
//! same copies hold the same records, whichever way they saw them.

use crate::record::{RawRecord, RecordSet};

/// Take `record` into `set` if it beats the copy there. Returns whether the
/// set changed.
pub(crate) fn join(set: &mut RecordSet, record: RawRecord) -> bool {
    match set.get(&record.key) {
        Some(current) if !beats(&record, current) => false,
        _ => {
            set.insert(record.key.clone(), record);
            true
        }
    }
}

/// Whether `new` replaces `old`: a greater version, or the same version with
/// a greater content hash. The second only happens when two devices share
/// an id; deciding by content still leaves them agreeing.
fn beats(new: &RawRecord, old: &RawRecord) -> bool {
    match new.version.cmp(&old.version) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => new.digest() > old.digest(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::FixedEnv;
    use crate::Kind;
    use crate::record::tests::{deleted, live, version};

    #[test]
    fn the_later_copy_wins_and_a_deletion_is_a_copy() {
        let mut set = RecordSet::new();
        assert!(join(
            &mut set,
            live(Kind::Host, "h", version(1, 'a'), json!({"name": "one"}))
        ));
        assert!(join(
            &mut set,
            live(Kind::Host, "h", version(3, 'b'), json!({"name": "three"}))
        ));
        assert!(!join(
            &mut set,
            live(Kind::Host, "h", version(2, 'c'), json!({"name": "two"}))
        ));
        assert!(join(&mut set, deleted(Kind::Host, "h", version(4, 'a'))));
        assert!(set.values().next().unwrap().is_deleted());
        assert!(!join(
            &mut set,
            live(Kind::Host, "h", version(3, 'b'), json!({"name": "three"}))
        ));
    }

    #[test]
    fn the_same_version_twice_settles_on_one_content() {
        let one = live(Kind::Host, "h", version(1, 'a'), json!({"name": "one"}));
        let two = live(Kind::Host, "h", version(1, 'a'), json!({"name": "two"}));
        let mut first = RecordSet::new();
        join(&mut first, one.clone());
        join(&mut first, two.clone());
        let mut second = RecordSet::new();
        join(&mut second, two);
        join(&mut second, one);
        assert_eq!(first, second);
    }

    /// Joining is commutative, associative and idempotent: random copies
    /// joined in random orders and groupings always end the same.
    #[test]
    fn the_order_copies_come_in_does_not_matter() {
        let mut env = FixedEnv::new(0, 11);
        for _ in 0..200 {
            let mut copies = Vec::new();
            for _ in 0..12 {
                let roll = env.next_u64();
                let id = ["a", "b", "c"][(roll % 3) as usize];
                let by = ['a', 'b', 'c'][(roll / 3 % 3) as usize];
                let at = version(roll / 9 % 4, by);
                copies.push(if (roll / 36).is_multiple_of(4) {
                    deleted(Kind::Group, id, at)
                } else {
                    live(
                        Kind::Group,
                        id,
                        at,
                        json!({"name": format!("n{}", roll % 5)}),
                    )
                });
            }
            let mut expected = RecordSet::new();
            for copy in &copies {
                join(&mut expected, copy.clone());
            }
            // Shuffle, join half into one set and half into another, then
            // join the two and some copies again.
            let mut shuffled = copies.clone();
            for i in (1..shuffled.len()).rev() {
                let j = (env.next_u64() % (i as u64 + 1)) as usize;
                shuffled.swap(i, j);
            }
            let (left, right) = shuffled.split_at(shuffled.len() / 2);
            let (mut a, mut b) = (RecordSet::new(), RecordSet::new());
            left.iter().for_each(|copy| {
                join(&mut a, copy.clone());
            });
            right.iter().for_each(|copy| {
                join(&mut b, copy.clone());
            });
            for copy in b.into_values().chain(copies.iter().take(3).cloned()) {
                join(&mut a, copy);
            }
            assert_eq!(a, expected);
        }
    }
}
