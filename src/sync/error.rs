//! Why a sync job stopped, and how to say so.

use gpui_kit::SharedString;
use shellrs_sync::{StoreError, SyncError};

use crate::i18n::{t, tn};

/// Why a sync job stopped. Kept as a value and put into words when shown,
/// so it reads in the language of the moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobError {
    Sync(SyncError),
    /// This copy cannot sync: no keychain to keep the keys in.
    Unavailable,
    /// The keychain has no sync keys, or keys it cannot read: deleted, or
    /// never saved.
    NoKeyring,
    /// The keychain refused, in its own words.
    Keychain(SharedString),
    /// The database refused a round's changes, in its own words.
    NotSaved(SharedString),
    /// The keychain has no password for the WebDAV server.
    NoLogin,
    /// A round or another job runs: one at a time.
    InProgress,
    /// Every try met a change made meanwhile, the user's or another
    /// device's: the next round will do.
    Busy,
}

impl From<SyncError> for JobError {
    fn from(error: SyncError) -> Self {
        Self::Sync(error)
    }
}

impl JobError {
    pub fn describe(&self) -> SharedString {
        match self {
            Self::Sync(error) => describe_sync(error),
            Self::Unavailable => t!("sync.error.unavailable"),
            Self::NoKeyring => t!("sync.error.no_keyring"),
            Self::Keychain(message) | Self::NotSaved(message) => message.clone(),
            Self::NoLogin => t!("sync.error.no_login"),
            Self::InProgress => t!("sync.error.in_progress"),
            Self::Busy => t!("sync.error.busy"),
        }
    }
}

fn describe_sync(error: &SyncError) -> SharedString {
    match error {
        SyncError::Store(error) => describe_store(error),
        SyncError::VaultMissing => t!("sync.error.vault_missing"),
        SyncError::VaultExists => t!("sync.error.vault_exists"),
        SyncError::VaultTooNew(_) => t!("sync.error.vault_too_new"),
        SyncError::BadVault(reason) => t!("sync.error.bad_vault", reason = reason),
        SyncError::WrongPassword => t!("sync.error.wrong_password"),
        SyncError::NeedsPassword => t!("sync.error.needs_password"),
        SyncError::VaultReplaced => t!("sync.error.vault_replaced"),
        SyncError::StateUnreadable(reason) => t!("sync.error.state_unreadable", reason = reason),
        SyncError::MassDelete { count, of } => {
            tn!("sync.error.mass_delete", *count as usize, of = of)
        }
        SyncError::ReadOnly { .. } => t!("sync.error.read_only"),
        SyncError::Random => t!("sync.error.random"),
    }
}

fn describe_store(error: &StoreError) -> SharedString {
    match error {
        StoreError::NotFound => t!("sync.error.store.not_found"),
        StoreError::PreconditionFailed => t!("sync.error.store.changed"),
        StoreError::TooLarge => t!("sync.error.store.too_large"),
        StoreError::Timeout => t!("sync.error.store.timeout"),
        StoreError::Unauthorized => t!("sync.error.store.unauthorized"),
        StoreError::Unavailable(reason) => t!("sync.error.store.unavailable", reason = reason),
        StoreError::Io(reason) => t!("sync.error.store.io", reason = reason),
    }
}
