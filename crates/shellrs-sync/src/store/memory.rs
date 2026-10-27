//! A store in memory, for tests here and in the app: it keeps every call
//! it gets and can be told to fail.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::{Fetched, PutCondition, RemoteFile, SyncStore};
use crate::StoreError;

/// A call a `MemoryStore` got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    List(String),
    Get(String),
    Put(String),
    Delete(String),
}

/// Which calls a failure or a race is for.
type Matcher = fn(&Op) -> bool;

#[derive(Default)]
struct Inner {
    files: BTreeMap<String, (Vec<u8>, String)>,
    next_tag: u64,
    log: Vec<Op>,
    /// Failures to give, each for the first call it matches.
    failures: Vec<(Matcher, StoreError)>,
    /// Files another writer stores just before the first call each matches.
    races: Vec<(Matcher, String, Vec<u8>)>,
}

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next call `matches` picks with `error`.
    pub fn fail_next(&self, matches: Matcher, error: StoreError) {
        self.lock().failures.push((matches, error));
    }

    /// Just before the next call `matches` picks, store `bytes` at `path`
    /// as another writer would: the call then sees the other's file.
    pub fn race_next(&self, matches: Matcher, path: &str, bytes: Vec<u8>) {
        self.lock().races.push((matches, path.to_owned(), bytes));
    }

    /// Forget the failures and races not given yet.
    pub fn clear_failures(&self) {
        let mut inner = self.lock();
        inner.failures.clear();
        inner.races.clear();
    }

    /// Every call so far, oldest first.
    pub fn operations(&self) -> Vec<Op> {
        self.lock().log.clone()
    }

    pub fn clear_operations(&self) {
        self.lock().log.clear();
    }

    /// The file as stored, bypassing everything.
    pub fn raw(&self, path: &str) -> Option<Vec<u8>> {
        self.lock().files.get(path).map(|(bytes, _)| bytes.clone())
    }

    /// Store a file as another writer would, with a new tag.
    pub fn set_raw(&self, path: &str, bytes: Vec<u8>) {
        let mut inner = self.lock();
        let tag = inner.tag();
        inner.files.insert(path.to_owned(), (bytes, tag));
    }

    pub fn remove_raw(&self, path: &str) {
        self.lock().files.remove(path);
    }

    pub fn paths(&self) -> Vec<String> {
        self.lock().files.keys().cloned().collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn begin(&self, op: Op) -> Result<std::sync::MutexGuard<'_, Inner>, StoreError> {
        let mut inner = self.lock();
        if let Some(i) = inner.failures.iter().position(|(matches, _)| matches(&op)) {
            let (_, error) = inner.failures.remove(i);
            inner.log.push(op);
            return Err(error);
        }
        if let Some(i) = inner.races.iter().position(|(matches, _, _)| matches(&op)) {
            let (_, path, bytes) = inner.races.remove(i);
            let tag = inner.tag();
            inner.files.insert(path, (bytes, tag));
        }
        inner.log.push(op);
        Ok(inner)
    }
}

impl Inner {
    fn tag(&mut self) -> String {
        self.next_tag += 1;
        format!("t{}", self.next_tag)
    }
}

impl SyncStore for MemoryStore {
    fn list(&self, dir: String) -> Result<Vec<RemoteFile>, StoreError> {
        let prefix = format!("{dir}/");
        let inner = self.begin(Op::List(dir))?;
        Ok(inner
            .files
            .iter()
            .filter_map(|(path, (bytes, tag))| {
                let name = path.strip_prefix(&prefix)?;
                (!name.contains('/')).then(|| RemoteFile {
                    name: name.to_owned(),
                    etag: tag.clone(),
                    size: bytes.len() as u64,
                })
            })
            .collect())
    }

    fn get(&self, path: String, max_bytes: u64) -> Result<Fetched, StoreError> {
        let inner = self.begin(Op::Get(path.clone()))?;
        let (bytes, tag) = inner.files.get(&path).ok_or(StoreError::NotFound)?;
        if bytes.len() as u64 > max_bytes {
            return Err(StoreError::TooLarge);
        }
        Ok(Fetched {
            bytes: bytes.clone(),
            etag: tag.clone(),
        })
    }

    fn put(&self, path: String, bytes: Vec<u8>, cond: PutCondition) -> Result<String, StoreError> {
        let mut inner = self.begin(Op::Put(path.clone()))?;
        let current = inner.files.get(&path).map(|(_, tag)| tag.clone());
        let allowed = match (&cond, &current) {
            (PutCondition::Overwrite, _) | (PutCondition::Absent, None) => true,
            (PutCondition::Matches(expected), Some(tag)) => expected == tag,
            _ => false,
        };
        if !allowed {
            return Err(StoreError::PreconditionFailed);
        }
        let tag = inner.tag();
        inner.files.insert(path, (bytes, tag.clone()));
        Ok(tag)
    }

    fn delete(&self, path: String) -> Result<(), StoreError> {
        let mut inner = self.begin(Op::Delete(path.clone()))?;
        inner
            .files
            .remove(&path)
            .map(drop)
            .ok_or(StoreError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_change_with_every_write_and_conditions_hold() {
        let store = MemoryStore::new();
        let one = store
            .put("d/a".into(), vec![1], PutCondition::Absent)
            .unwrap();
        assert_eq!(
            store.put("d/a".into(), vec![2], PutCondition::Absent),
            Err(StoreError::PreconditionFailed)
        );
        let two = store
            .put("d/a".into(), vec![2], PutCondition::Matches(one.clone()))
            .unwrap();
        assert_ne!(one, two);
        assert_eq!(
            store.put("d/a".into(), vec![3], PutCondition::Matches(one)),
            Err(StoreError::PreconditionFailed)
        );
        store
            .put("d/sub/b".into(), vec![9], PutCondition::Overwrite)
            .unwrap();
        let listed = store.list("d".into()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].etag, two);
        assert_eq!(store.list("nowhere".into()).unwrap(), vec![]);
        assert_eq!(store.get("d/a".into(), 0), Err(StoreError::TooLarge));
        assert_eq!(store.get("d/a".into(), 9).unwrap().bytes, vec![2]);
    }

    #[test]
    fn failures_come_once_where_asked() {
        let store = MemoryStore::new();
        store.fail_next(|op| matches!(op, Op::List(_)), StoreError::Timeout);
        assert_eq!(store.list("d".into()), Err(StoreError::Timeout));
        assert_eq!(store.list("d".into()), Ok(vec![]));
        assert_eq!(
            store.operations(),
            vec![Op::List("d".into()), Op::List("d".into())]
        );
    }
}
