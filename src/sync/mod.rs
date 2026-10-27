//! 同步: the hosts and the rest kept alike on the user's computers through
//! a folder they choose (one a cloud drive syncs), with `shellrs_sync`
//! doing the merging and the encryption.
//!
//! [`SyncService`] runs the rounds and the jobs that set sync up, change its
//! password and turn it off; the workspace says when (starting, the window
//! coming forward, a pause after an edit, 立即同步, quitting) and keeps the
//! folder in the settings. The keys stay in the keychain, the state in the
//! database, and the secrets go where the store keeps them.

mod error;
mod remote_dialog;
mod service;
mod sync_dialog;
mod worker;

pub use error::JobError;
pub use remote_dialog::{RemoteDialog, RemoteKind, open_remote_dialog};
pub use service::{
    Attention, EDIT_PAUSE, OpenStore, SyncEvent, SyncPhase, SyncService, SyncServices, SyncSnapshot,
};
pub use sync_dialog::{
    JoinReason, MIN_PASSWORD, PasswordDialog, open_password_dialog, open_turn_off_dialog,
};
