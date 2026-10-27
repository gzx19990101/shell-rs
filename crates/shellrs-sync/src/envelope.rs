//! A device file (`.srs`): a header in the clear, then the snapshot,
//! encrypted and authenticated.
//!
//! ```text
//! "SRSY" | version (1 byte, 1) | vault id (16) | key generation (4, big-endian) | nonce (24)
//! XChaCha20-Poly1305 ciphertext and tag
//! ```
//!
//! The header and the device id the file is named after are authenticated
//! with it, so a file renamed to another device's name, moved to another
//! vault or given another generation fails to open.

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::env::random_array;
use crate::vault::Keyring;
use crate::{DeviceId, Env, SyncError};

const MAGIC: &[u8; 4] = b"SRSY";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 16 + 4 + 24;

/// Why a file does not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// Not a device file, or cut short.
    NotOurs,
    /// Written in a newer envelope version.
    TooNew(u8),
    /// From another vault: one made before sync was reset.
    OtherVault,
    /// Encrypted with a key generation this keyring does not have.
    UnknownGeneration(u32),
    /// Tampered with, damaged or renamed.
    Damaged,
}

/// Encrypt `snapshot` as `device`'s file with the keyring's newest key.
pub(crate) fn seal(
    snapshot: &[u8],
    device: &DeviceId,
    keyring: &Keyring,
    env: &mut dyn Env,
) -> Result<Vec<u8>, SyncError> {
    let generation = keyring.current_generation();
    let key = keyring.key(generation).expect("the current key is held");
    let nonce: [u8; 24] = random_array(env)?;
    let mut out = Vec::with_capacity(HEADER_LEN + snapshot.len() + 16);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&keyring.vault_id_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(&nonce);
    let aad = aad(&out, device);
    let sealed = XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: snapshot,
                aad: &aad,
            },
        )
        .map_err(|_| SyncError::Random)?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// The snapshot in `file`, which must be `device`'s.
pub(crate) fn open(
    file: &[u8],
    device: &DeviceId,
    keyring: &Keyring,
) -> Result<Vec<u8>, OpenError> {
    if file.len() < HEADER_LEN + 16 || !file.starts_with(MAGIC) {
        return Err(OpenError::NotOurs);
    }
    let (header, sealed) = file.split_at(HEADER_LEN);
    if header[4] != VERSION {
        return Err(if header[4] > VERSION {
            OpenError::TooNew(header[4])
        } else {
            OpenError::NotOurs
        });
    }
    if header[5..21] != keyring.vault_id_bytes() {
        return Err(OpenError::OtherVault);
    }
    let generation = u32::from_be_bytes(header[21..25].try_into().expect("4 bytes"));
    let key = keyring
        .key(generation)
        .ok_or(OpenError::UnknownGeneration(generation))?;
    let nonce: [u8; 24] = header[25..].try_into().expect("24 bytes");
    XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: sealed,
                aad: &aad(header, device),
            },
        )
        .map_err(|_| OpenError::Damaged)
}

fn aad(header: &[u8], device: &DeviceId) -> Vec<u8> {
    let mut aad = header.to_vec();
    aad.extend_from_slice(device.as_str().as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use crate::vault::tests::vault;
    use crate::{FixedEnv, rotate_key};

    fn keyring() -> (MemoryStore, FixedEnv, Keyring) {
        let store = MemoryStore::new();
        let mut env = FixedEnv::new(0, 3);
        let keyring = vault(&store, &mut env);
        (store, env, keyring)
    }

    fn device(name: &str) -> DeviceId {
        DeviceId::parse(name).unwrap()
    }

    #[test]
    fn a_file_opens_as_its_device_only() {
        let (_, mut env, keyring) = keyring();
        let me = device("aaaaaaaaaaaaaaaa");
        let file = seal(b"snapshot", &me, &keyring, &mut env).unwrap();
        assert_eq!(open(&file, &me, &keyring).unwrap(), b"snapshot");
        assert_eq!(
            open(&file, &device("bbbbbbbbbbbbbbbb"), &keyring),
            Err(OpenError::Damaged)
        );
    }

    #[test]
    fn any_changed_byte_is_noticed() {
        let (_, mut env, keyring) = keyring();
        let me = device("aaaaaaaaaaaaaaaa");
        let file = seal(b"snapshot", &me, &keyring, &mut env).unwrap();
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 1;
            assert!(open(&bad, &me, &keyring).is_err(), "byte {i}");
        }
        assert_eq!(open(&file[..30], &me, &keyring), Err(OpenError::NotOurs));
        assert_eq!(open(b"PK\x03\x04", &me, &keyring), Err(OpenError::NotOurs));
    }

    #[test]
    fn each_reason_a_file_does_not_open_is_told() {
        let (store, mut env, keyring) = keyring();
        let me = device("aaaaaaaaaaaaaaaa");
        let file = seal(b"x", &me, &keyring, &mut env).unwrap();

        let mut newer = file.clone();
        newer[4] = 2;
        assert_eq!(open(&newer, &me, &keyring), Err(OpenError::TooNew(2)));

        let other = vault(&MemoryStore::new(), &mut FixedEnv::new(0, 9));
        assert_eq!(open(&file, &me, &other), Err(OpenError::OtherVault));

        let rotated = rotate_key(&store, &keyring, &mut env).unwrap();
        let file = seal(b"x", &me, &rotated, &mut env).unwrap();
        assert_eq!(
            open(&file, &me, &keyring),
            Err(OpenError::UnknownGeneration(2))
        );
        assert_eq!(open(&file, &me, &rotated).unwrap(), b"x");
    }
}
