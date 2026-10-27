//! Where files live: anything that can list, read, write and delete them.
//!
//! Paths are relative to the root the user chose and use `/`. Arguments are
//! owned, so a store can be written in Swift or Kotlin later and handed in
//! through the bindings (iCloud Drive wants the system's file coordination,
//! for one).

mod local;
mod memory;
mod s3;
mod webdav;

pub use local::LocalFolderStore;
pub(crate) use local::tag_base;
pub use memory::{MemoryStore, Op};
pub use s3::{S3Location, S3Store};
pub use webdav::WebDavStore;

use crate::StoreError;

/// A file in a listing. `etag` changes whenever the file does; equal tags
/// mean the file need not be read again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteFile {
    pub name: String,
    pub etag: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub etag: String,
}

/// When a write may happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutCondition {
    Overwrite,
    /// Only if there is no such file yet.
    Absent,
    /// Only if the file is still the one with this tag.
    Matches(String),
}

pub trait SyncStore: Send + Sync {
    /// The files directly in `dir`, not in its subfolders. A folder that
    /// does not exist lists as empty.
    fn list(&self, dir: String) -> Result<Vec<RemoteFile>, StoreError>;
    /// The file, or `TooLarge` without reading it all when it is larger
    /// than `max_bytes`.
    fn get(&self, path: String, max_bytes: u64) -> Result<Fetched, StoreError>;
    /// Write the file, making the folders it needs; returns its new tag.
    fn put(&self, path: String, bytes: Vec<u8>, cond: PutCondition) -> Result<String, StoreError>;
    fn delete(&self, path: String) -> Result<(), StoreError>;
}
