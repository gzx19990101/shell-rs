//! A folder on this computer, which a cloud drive (iCloud Drive, Dropbox,
//! OneDrive) or a network share may be syncing.
//!
//! Such folders have their ways, each met here:
//! - A file being written must never be seen half done: writes go to a
//!   temporary file beside it, which then replaces it.
//! - Reading a file can make the drive download it, so tags come from the
//!   file's metadata, never its contents.
//! - Some keep times to the second or two (FAT, exFAT, SMB), so a file
//!   rewritten within that time may keep its time and size. A file changed
//!   within `RACY` of being looked at gets a tag that matches nothing, so it
//!   is read again next time (git's rule for the same problem).
//! - A drive may hold a file open (OneDrive, virus scanners): replacing it
//!   is retried for a while on Windows.
//! - A drive or share can hang: every call has a time limit.

use std::fs::{self, File, Metadata};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Fetched, PutCondition, RemoteFile, SyncStore};
use crate::StoreError;

/// How close to now a file's time must be for its tag to be in doubt.
const RACY: Duration = Duration::from_secs(3);
/// Temporary files left by a write that never finished are removed once
/// this old.
const STALE_TEMP: Duration = Duration::from_secs(3600);

pub struct LocalFolderStore {
    root: PathBuf,
    timeout: Duration,
}

impl LocalFolderStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn resolve(&self, path: &str) -> Result<PathBuf, StoreError> {
        let mut out = self.root.clone();
        for part in path.split('/') {
            let plain = !part.is_empty()
                && part != "."
                && part != ".."
                && !part.contains(['\\', ':', '\0']);
            if !plain {
                return Err(StoreError::Io(format!("not a path in the store: {path}")));
            }
            out.push(part);
        }
        Ok(out)
    }
}

/// Run `work` on a thread of its own and give up waiting after `timeout`.
/// A call that hangs is left running; nothing else waits for it.
fn within<T: Send + 'static>(
    timeout: Duration,
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("sync-folder".into())
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(io_error)?;
    receiver
        .recv_timeout(timeout)
        .map_err(|_| StoreError::Timeout)?
}

fn io_error(error: io::Error) -> StoreError {
    match error.kind() {
        io::ErrorKind::NotFound => StoreError::NotFound,
        _ => StoreError::Io(error.to_string()),
    }
}

/// A file's tag: its identity, time and size, or one that matches nothing
/// while the time is too recent to trust.
fn tag(meta: &Metadata) -> String {
    let now = SystemTime::now();
    let modified = meta.modified().ok();
    let nanos = modified
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_nanos());
    #[cfg(unix)]
    let base = {
        use std::os::unix::fs::MetadataExt as _;
        format!("{:x}-{nanos}-{}", meta.ino(), meta.len())
    };
    #[cfg(not(unix))]
    let base = format!("{nanos}-{}", meta.len());
    let racy = modified.is_none_or(|time| now.duration_since(time).map_or(true, |age| age < RACY));
    if racy {
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        format!("{base}~r{now}")
    } else {
        base
    }
}

/// The part of a tag that names the file itself, without the doubt.
pub(crate) fn tag_base(tag: &str) -> &str {
    tag.split_once("~r").map_or(tag, |(base, _)| base)
}

fn temp_name(target: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = target
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    let unique = format!(
        "{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    target.with_file_name(format!(".{name}.{unique}.tmp"))
}

/// Replace `target` with `temp`, retrying on Windows while something holds
/// the file.
fn replace(temp: &Path, target: &Path) -> io::Result<()> {
    let mut attempt = 0;
    loop {
        match fs::rename(temp, target) {
            Err(error)
                if cfg!(windows)
                    && error.kind() == io::ErrorKind::PermissionDenied
                    && attempt < 5 =>
            {
                attempt += 1;
                thread::sleep(Duration::from_millis(200));
            }
            result => return result,
        }
    }
}

fn write_temp(temp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(temp)?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl SyncStore for LocalFolderStore {
    fn list(&self, dir: String) -> Result<Vec<RemoteFile>, StoreError> {
        let dir = self.resolve(&dir)?;
        within(self.timeout, move || {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(error) => return Err(io_error(error)),
            };
            let mut out = Vec::new();
            for entry in entries {
                let entry = entry.map_err(io_error)?;
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if name.starts_with('.') {
                    // Our own temporary files, a drive's placeholders and
                    // the like; ours are cleared once clearly abandoned.
                    let stale = meta
                        .modified()
                        .ok()
                        .and_then(|time| SystemTime::now().duration_since(time).ok())
                        .is_some_and(|age| age > STALE_TEMP);
                    if name.ends_with(".tmp") && stale {
                        let _ = fs::remove_file(entry.path());
                    }
                    continue;
                }
                if meta.is_file() {
                    out.push(RemoteFile {
                        etag: tag(&meta),
                        size: meta.len(),
                        name,
                    });
                }
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
    }

    fn get(&self, path: String, max_bytes: u64) -> Result<Fetched, StoreError> {
        let path = self.resolve(&path)?;
        within(self.timeout, move || {
            let meta = fs::metadata(&path).map_err(io_error)?;
            if meta.len() > max_bytes {
                return Err(StoreError::TooLarge);
            }
            // The tag is taken before reading: a write meanwhile shows as a
            // change next time rather than being missed.
            let etag = tag(&meta);
            let mut bytes = Vec::new();
            File::open(&path)
                .and_then(|file| {
                    file.take(max_bytes.saturating_add(1))
                        .read_to_end(&mut bytes)
                })
                .map_err(io_error)?;
            if bytes.len() as u64 > max_bytes {
                return Err(StoreError::TooLarge);
            }
            Ok(Fetched { bytes, etag })
        })
    }

    fn put(&self, path: String, bytes: Vec<u8>, cond: PutCondition) -> Result<String, StoreError> {
        let target = self.resolve(&path)?;
        within(self.timeout, move || {
            if let Some(dir) = target.parent() {
                fs::create_dir_all(dir).map_err(io_error)?;
            }
            let temp = temp_name(&target);
            if let Err(error) = write_temp(&temp, &bytes) {
                let _ = fs::remove_file(&temp);
                return Err(io_error(error));
            }
            let placed = match &cond {
                PutCondition::Overwrite => replace(&temp, &target).map_err(io_error),
                PutCondition::Absent => match fs::hard_link(&temp, &target) {
                    // A link fails if the file is there: no race with
                    // another writer. Drives without links fall back to
                    // checking first.
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        Err(StoreError::PreconditionFailed)
                    }
                    Err(_) if target.exists() => Err(StoreError::PreconditionFailed),
                    Err(_) => replace(&temp, &target).map_err(io_error),
                },
                // Checked, then replaced: another writer between the two
                // goes unseen, which a folder offers no way to prevent.
                PutCondition::Matches(expected) => match fs::metadata(&target) {
                    Ok(meta) if tag_base(&tag(&meta)) == tag_base(expected) => {
                        replace(&temp, &target).map_err(io_error)
                    }
                    Ok(_) => Err(StoreError::PreconditionFailed),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        Err(StoreError::PreconditionFailed)
                    }
                    Err(error) => Err(io_error(error)),
                },
            };
            let _ = fs::remove_file(&temp);
            placed?;
            fs::metadata(&target)
                .map(|meta| tag(&meta))
                .map_err(io_error)
        })
    }

    fn delete(&self, path: String) -> Result<(), StoreError> {
        let path = self.resolve(&path)?;
        within(self.timeout, move || {
            fs::remove_file(&path).map_err(io_error)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, LocalFolderStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFolderStore::new(dir.path());
        (dir, store)
    }

    #[test]
    fn a_file_reads_back_as_written() {
        let (_dir, store) = store();
        let tag = store
            .put("a/b/c.srs".into(), b"hello".to_vec(), PutCondition::Absent)
            .unwrap();
        let fetched = store.get("a/b/c.srs".into(), 100).unwrap();
        assert_eq!(fetched.bytes, b"hello");
        assert_eq!(tag_base(&fetched.etag), tag_base(&tag));
        assert_eq!(store.get("a/b/c.srs".into(), 2), Err(StoreError::TooLarge));
        assert_eq!(store.get("a/b/none".into(), 2), Err(StoreError::NotFound));
        store.delete("a/b/c.srs".into()).unwrap();
        assert_eq!(store.delete("a/b/c.srs".into()), Err(StoreError::NotFound));
    }

    #[test]
    fn conditions_hold() {
        let (_dir, store) = store();
        let first = store
            .put("f".into(), b"1".to_vec(), PutCondition::Absent)
            .unwrap();
        assert_eq!(
            store.put("f".into(), b"2".to_vec(), PutCondition::Absent),
            Err(StoreError::PreconditionFailed)
        );
        let second = store
            .put(
                "f".into(),
                b"2".to_vec(),
                PutCondition::Matches(first.clone()),
            )
            .unwrap();
        assert_ne!(tag_base(&first), tag_base(&second));
        assert_eq!(
            store.put("f".into(), b"3".to_vec(), PutCondition::Matches(first)),
            Err(StoreError::PreconditionFailed)
        );
        assert_eq!(
            store.put("g".into(), b"3".to_vec(), PutCondition::Matches(second)),
            Err(StoreError::PreconditionFailed)
        );
        assert_eq!(store.get("f".into(), 9).unwrap().bytes, b"2");
    }

    #[test]
    fn a_file_just_written_is_always_read_again() {
        let (_dir, store) = store();
        store
            .put("d/x.srs".into(), b"1".to_vec(), PutCondition::Overwrite)
            .unwrap();
        let one = store.list("d".into()).unwrap();
        let two = store.list("d".into()).unwrap();
        assert_ne!(one[0].etag, two[0].etag);
        assert_eq!(tag_base(&one[0].etag), tag_base(&two[0].etag));
    }

    #[test]
    fn listing_skips_what_is_not_a_file_of_ours_and_clears_stale_temp_files() {
        let (dir, store) = store();
        assert_eq!(store.list("d".into()).unwrap(), vec![]);
        let d = dir.path().join("d");
        fs::create_dir_all(d.join("sub")).unwrap();
        fs::write(d.join("x.srs"), b"x").unwrap();
        fs::write(d.join(".x.srs.icloud"), b"").unwrap();
        fs::write(d.join(".fresh.tmp"), b"").unwrap();
        let stale = d.join(".x.srs.1-2-3.tmp");
        fs::write(&stale, b"").unwrap();
        File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(7200))
            .unwrap();
        let names: Vec<_> = store
            .list("d".into())
            .unwrap()
            .into_iter()
            .map(|file| file.name)
            .collect();
        assert_eq!(names, ["x.srs"]);
        assert!(!stale.exists());
        assert!(d.join(".fresh.tmp").exists());
    }

    /// Listing reads metadata only: a file nobody may read still lists.
    #[cfg(unix)]
    #[test]
    fn listing_does_not_read_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, store) = store();
        let file = dir.path().join("d/x.srs");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(store.list("d".into()).unwrap().len(), 1);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn paths_stay_inside_the_folder() {
        let (_dir, store) = store();
        for path in ["../x", "a/../../x", "/x", "a//b", "a\\b", "c:x"] {
            assert!(
                matches!(store.get(path.into(), 1), Err(StoreError::Io(_))),
                "{path}"
            );
        }
    }

    #[test]
    fn a_call_that_hangs_times_out() {
        let result = within(Duration::from_millis(20), || {
            thread::sleep(Duration::from_millis(300));
            Ok(())
        });
        assert_eq!(result, Err(StoreError::Timeout));
    }
}
