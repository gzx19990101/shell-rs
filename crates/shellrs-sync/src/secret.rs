//! Secrets: sign-in passwords, passphrases and private keys. They sync as
//! records of their own (`secret.*`), so changing a password and renaming
//! its host never overwrite each other, but are never seen in the clear
//! outside the encrypted device files.
//!
//! On a device they live in the app's keychain and key folder. In the sync
//! state, which the app keeps in its database, they are sealed with the
//! vault's data key (`seal`), and the digest of what was uploaded leaves
//! their content out. Values going to and from the app are `Secret`s,
//! which show nothing in `Debug` and are wiped when dropped. While a round
//! merges them they are JSON strings in memory for a moment, which cannot
//! be wiped. Secrets always sync: whoever wants none in the cloud does
//! not turn sync on.

use std::fmt;

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::env::random_array;
use crate::record::{RawRecord, RecordSet};
use crate::vault::Keyring;
use crate::{Env, SyncError, hex};

/// The longest value a secret may have: a private key file at most, as
/// the app reads them.
pub(crate) const MAX_VALUE: usize = 64 * 1024;

/// A password, passphrase or private key: its `Debug` shows nothing, and
/// it is wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(…)")
    }
}

/// The password saved for signing in as `user` at `host:port`, shared by
/// every host that does, as the app keeps it. Its record's id is
/// `endpoint_secret_id` of the three, so two devices saving one make one
/// record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointSecret {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub value: Secret,
}

/// The id of the password record for `user` at `host:port`.
pub fn endpoint_secret_id(user: &str, host: &str, port: u16) -> String {
    let mut hash = Sha256::new();
    hash.update(user.as_bytes());
    hash.update([0]);
    hash.update(host.as_bytes());
    hash.update([0]);
    hash.update(port.to_string().as_bytes());
    hex::encode(&hash.finalize()[..16])
}

/// A state's secret records, encrypted with a data key of the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sealed {
    pub generation: u32,
    pub nonce: [u8; 24],
    pub sealed: Vec<u8>,
}

/// Seal `records`, every one a secret, with the keyring's newest key.
pub(crate) fn seal(
    records: &RecordSet,
    keys: &Keyring,
    env: &mut dyn Env,
) -> Result<Sealed, SyncError> {
    let values: Vec<Value> = records.values().map(RawRecord::to_json).collect();
    let plain = Zeroizing::new(serde_json::to_vec(&values).expect("records serialize"));
    let generation = keys.current_generation();
    let key = keys.key(generation).expect("the current key is held");
    let nonce: [u8; 24] = random_array(env)?;
    let sealed = XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &aad(keys, generation),
            },
        )
        .map_err(|_| SyncError::Random)?;
    Ok(Sealed {
        generation,
        nonce,
        sealed,
    })
}

/// The records `seal` sealed, or `None` when these keys do not open them
/// (the vault was reset) or what they hold is not secrets.
pub(crate) fn open(sealed: &Sealed, keys: &Keyring) -> Option<RecordSet> {
    let key = keys.key(sealed.generation)?;
    let plain = XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .decrypt(
            &XNonce::from(sealed.nonce),
            Payload {
                msg: &sealed.sealed,
                aad: &aad(keys, sealed.generation),
            },
        )
        .ok()
        .map(Zeroizing::new)?;
    let values: Vec<Value> = serde_json::from_slice(&plain).ok()?;
    let mut records = RecordSet::new();
    for value in &values {
        let record = RawRecord::from_json(value).ok()?;
        if !record.key.kind.is_secret() {
            return None;
        }
        records.insert(record.key.clone(), record);
    }
    Some(records)
}

/// Binds the sealed records to their vault and key, not to the device:
/// a state given a new device id still opens.
fn aad(keys: &Keyring, generation: u32) -> Vec<u8> {
    let mut aad = b"shellrs-sync state".to_vec();
    aad.extend_from_slice(&keys.vault_id_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::record::tests::{deleted, live, version};
    use crate::store::MemoryStore;
    use crate::vault::tests::vault;
    use crate::{FixedEnv, Kind, RecordKey, rotate_key};

    fn secrets() -> RecordSet {
        let password = live(
            Kind::SecretPassword,
            &endpoint_secret_id("root", "10.0.0.1", 22),
            version(5, 'a'),
            json!({"user": "root", "host": "10.0.0.1", "port": 22, "value": "hunter2"}),
        );
        let gone = deleted(Kind::SecretCredential, "c1", version(6, 'b'));
        [password, gone]
            .into_iter()
            .map(|record| (record.key.clone(), record))
            .collect()
    }

    #[test]
    fn a_secret_shows_nothing() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret:?}"), "Secret(…)");
        let endpoint = EndpointSecret {
            user: "root".into(),
            host: "web".into(),
            port: 22,
            value: secret,
        };
        assert!(!format!("{endpoint:?}").contains("hunter2"));
    }

    /// The id is the format: the same endpoint names the same record in
    /// every version.
    #[test]
    fn an_endpoint_names_its_password() {
        assert_eq!(
            endpoint_secret_id("root", "10.0.0.1", 22),
            "d77135a34ae21caa8c447127813e0d80"
        );
        assert_ne!(
            endpoint_secret_id("root", "10.0.0.1", 22),
            endpoint_secret_id("root", "10.0.0.1", 2222)
        );
        assert_ne!(
            endpoint_secret_id("ro", "ot10.0.0.1", 22),
            endpoint_secret_id("root", "10.0.0.1", 22)
        );
        assert!(RecordKey::is_valid_id(&endpoint_secret_id("", "h", 1)));
    }

    #[test]
    fn sealed_secrets_open_with_their_vault_only() {
        let store = MemoryStore::new();
        let mut env = FixedEnv::new(0, 1);
        let keys = vault(&store, &mut env);
        let sealed = seal(&secrets(), &keys, &mut env).unwrap();
        assert!(
            !sealed
                .sealed
                .windows(b"hunter2".len())
                .any(|w| w == b"hunter2")
        );
        assert_eq!(open(&sealed, &keys), Some(secrets()));

        // Still open once a new key generation comes.
        let rotated = rotate_key(&store, &keys, &mut env).unwrap();
        assert_eq!(open(&sealed, &rotated), Some(secrets()));

        let mut damaged = sealed.clone();
        damaged.sealed[3] ^= 1;
        assert_eq!(open(&damaged, &keys), None);
        let other = vault(&MemoryStore::new(), &mut FixedEnv::new(0, 2));
        assert_eq!(open(&sealed, &other), None);
    }

    #[test]
    fn only_secrets_are_sealed_ones() {
        let store = MemoryStore::new();
        let mut env = FixedEnv::new(0, 1);
        let keys = vault(&store, &mut env);
        let host = live(Kind::Host, "h", version(1, 'a'), json!({"name": "web"}));
        let set = RecordSet::from([(host.key.clone(), host)]);
        let sealed = seal(&set, &keys, &mut env).unwrap();
        assert_eq!(open(&sealed, &keys), None);
    }
}
