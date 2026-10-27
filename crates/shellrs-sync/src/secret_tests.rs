//! Rounds with secrets: they travel like any record, but never show in
//! the clear in a state, and what an app could not read is not deleted.

use serde_json::json;

use crate::record::RecordSet;
use crate::record::tests::{live, version};
use crate::round::records_digest;
use crate::round_tests::{plant, read_file, setup};
use crate::secret::Sealed;
use crate::testing::{Device, credential, key_credential, password};
use crate::{
    Capabilities, Change, DeviceInfo, Kind, LocalSnapshot, Pushed, RecordData, RecordKey,
    RoundOptions, Secret, Unchanged, Warning, pull,
};

fn key(kind: Kind, id: &str) -> RecordKey {
    RecordKey::new(kind, id)
}

/// Whether `device`'s stored state shows `text` anywhere.
fn state_shows(device: &Device, text: &str) -> bool {
    let bytes = device.state.to_bytes();
    bytes.windows(text.len()).any(|w| w == text.as_bytes())
}

fn value(device: &Device, kind: Kind, id: &str) -> Option<String> {
    match device.get(kind, id)? {
        RecordData::Password(e) | RecordData::ProxyPassword(e) => Some(e.value.expose().into()),
        RecordData::CredentialPassword(s)
        | RecordData::Passphrase(s)
        | RecordData::PrivateKey(s) => Some(s.expose().into()),
        other => panic!("{other:?}"),
    }
}

/// A device with a key credential, its passphrase and key, a password
/// credential with its password, and an endpoint's password.
fn with_secrets(a: &mut Device) -> String {
    a.put("c1", key_credential("deploy key"));
    a.put("c1", RecordData::Passphrase(Secret::new("pass-c1")));
    a.put("c1", RecordData::PrivateKey(Secret::new("key-c1")));
    a.put("c2", credential("ops"));
    a.put("c2", RecordData::CredentialPassword(Secret::new("pw-c2")));
    let (id, data) = password("root", "web", "pw-web");
    a.put(&id, data);
    id
}

#[test]
fn secrets_reach_the_other_device_and_no_state_shows_them() {
    let (store, keys, mut a, mut b) = setup();
    let web = with_secrets(&mut a);
    a.sync(&store);
    let pulled = b.pull(&store).unwrap();
    let shown = format!("{:?}", pulled.changes);
    b.apply(&pulled);
    b.push(&store).unwrap();

    assert_eq!(b.data(), a.data());
    assert_eq!(
        value(&b, Kind::SecretPrivateKey, "c1").as_deref(),
        Some("key-c1")
    );
    assert_eq!(
        value(&b, Kind::SecretPassword, &web).as_deref(),
        Some("pw-web")
    );
    for text in ["pass-c1", "key-c1", "pw-c2", "pw-web"] {
        assert!(!shown.contains(text), "a change shows {text}");
        assert!(
            !state_shows(&a, text) && !state_shows(&b, text),
            "a state shows {text}"
        );
    }
    // In the file, which is encrypted whole.
    let file = read_file(&store, &keys, a.state.device());
    assert!(
        file.records
            .contains_key(&key(Kind::SecretPassphrase, "c1"))
    );
}

#[test]
fn one_endpoint_saved_twice_is_one_password_the_later() {
    let (store, _, mut a, mut b) = setup();
    let (id, first) = password("root", "web", "first");
    a.put(&id, first);
    b.wait(1000);
    let (_, second) = password("root", "web", "second");
    b.put(&id, second);
    for _ in 0..2 {
        a.sync(&store);
        b.sync(&store);
    }
    assert_eq!(
        value(&a, Kind::SecretPassword, &id).as_deref(),
        Some("second")
    );
    assert_eq!(a.data(), b.data());
}

#[test]
fn a_deleted_credential_takes_its_secrets_everywhere() {
    let (store, _, mut a, mut b) = setup();
    with_secrets(&mut a);
    a.sync(&store);
    b.sync(&store);
    // An app that left the credential's secrets behind: the round deletes
    // them for it.
    b.remove(Kind::Credential, "c1");
    b.sync(&store);
    assert_eq!(b.get(Kind::SecretPassphrase, "c1"), None);
    assert_eq!(b.get(Kind::SecretPrivateKey, "c1"), None);
    a.sync(&store);
    assert_eq!(a.get(Kind::SecretPrivateKey, "c1"), None);
    assert_eq!(a.data(), b.data());
    assert!(a.get(Kind::SecretCredential, "c2").is_some());
}

#[test]
fn a_credentials_secret_waits_for_a_credential_that_has_one() {
    let (store, _, mut a, mut b) = setup();
    a.put("c9", RecordData::Passphrase(Secret::new("pass-c9")));
    a.sync(&store);
    let pulled = b.pull(&store).unwrap();
    assert_eq!(pulled.changes, []);
    assert!(
        !pulled
            .report
            .warnings
            .iter()
            .any(|w| matches!(w, Warning::Parked { .. }))
    );
    b.apply(&pulled);

    // A password credential has no passphrase.
    a.put("c9", credential("ops"));
    a.sync(&store);
    b.sync(&store);
    assert_eq!(b.get(Kind::SecretPassphrase, "c9"), None);

    a.put("c9", key_credential("ops"));
    a.sync(&store);
    b.sync(&store);
    assert_eq!(
        value(&b, Kind::SecretPassphrase, "c9").as_deref(),
        Some("pass-c9")
    );
}

#[test]
fn secrets_not_read_are_neither_deleted_nor_given() {
    let (store, keys, mut a, mut b) = setup();
    let web = with_secrets(&mut a);
    a.sync(&store);
    b.sync(&store);

    b.keychain_ok = false;
    a.wait(1000);
    let (_, changed) = password("root", "web", "pw-new");
    a.put(&web, changed);
    a.sync(&store);
    let (report, _) = b.sync(&store);
    assert_eq!(report.local_deletes, 0);
    assert_eq!(
        value(&b, Kind::SecretPassword, &web).as_deref(),
        Some("pw-web")
    );
    // Its file still has them.
    let file = read_file(&store, &keys, b.state.device());
    assert!(
        file.records
            .contains_key(&key(Kind::SecretCredential, "c2"))
    );

    b.keychain_ok = true;
    b.sync(&store);
    assert_eq!(
        value(&b, Kind::SecretPassword, &web).as_deref(),
        Some("pw-new")
    );
    a.sync(&store);
    assert_eq!(a.data(), b.data());
}

#[test]
fn a_key_file_the_app_cannot_read_is_not_deleted() {
    let (store, _, mut a, mut b) = setup();
    with_secrets(&mut a);
    a.sync(&store);
    a.unreadable = vec![key(Kind::SecretPrivateKey, "c1")];
    let (report, _) = a.sync(&store);
    assert_eq!(report.local_deletes, 0);
    b.sync(&store);
    assert_eq!(
        value(&b, Kind::SecretPrivateKey, "c1").as_deref(),
        Some("key-c1")
    );
}

/// What `device` hands a round without reading its secrets: each one as
/// unchanged, with the edit time it has.
fn unread(device: &Device) -> LocalSnapshot {
    let mut local = device.local();
    let (secrets, records): (Vec<_>, Vec<_>) = local
        .records
        .into_iter()
        .partition(|record| record.data.kind().is_secret());
    local.records = records;
    local.unchanged = secrets
        .into_iter()
        .map(|record| Unchanged {
            key: RecordKey::new(record.data.kind(), record.id),
            edited_ms: record.edited_ms,
        })
        .collect();
    local
}

fn pull_from(
    device: &mut Device,
    store: &crate::MemoryStore,
    local: &LocalSnapshot,
) -> crate::Pulled {
    pull(
        store,
        &device.keys,
        &device.state,
        local,
        &Capabilities::ALL,
        &RoundOptions::default(),
        &mut device.env,
    )
    .unwrap()
}

/// A keychain is read for what changed only: the rest the state keeps.
#[test]
fn secrets_not_read_since_the_last_round_are_the_states_copies() {
    let (store, _, mut a, mut b) = setup();
    let web = with_secrets(&mut a);
    a.sync(&store);
    b.sync(&store);
    let local = unread(&b);
    assert_eq!(local.unchanged.len(), 4);
    for unchanged in &local.unchanged {
        assert_eq!(b.state.edit_seen(&unchanged.key), Some(unchanged.edited_ms));
    }
    let pulled = pull_from(&mut b, &store, &local);
    assert!(pulled.changes.is_empty(), "{:?}", pulled.changes);
    assert_eq!(pulled.report.local_deletes, 0);
    b.apply(&pulled);
    assert!(matches!(b.push(&store).unwrap(), Pushed::Unchanged));

    // Changed elsewhere, it comes all the same.
    a.wait(1000);
    let (_, changed) = password("root", "web", "pw-new");
    a.put(&web, changed);
    a.sync(&store);
    let local = unread(&b);
    let pulled = pull_from(&mut b, &store, &local);
    assert_eq!(
        pulled.changes.iter().map(Change::key).collect::<Vec<_>>(),
        [key(Kind::SecretPassword, &web)]
    );
    b.apply(&pulled);
    b.push(&store).unwrap();
    assert_eq!(
        value(&b, Kind::SecretPassword, &web).as_deref(),
        Some("pw-new")
    );
    a.sync(&store);
    assert_eq!(a.data(), b.data());
}

/// One the state does not have as vouched for is neither taken for it nor
/// for deleted: it is given again.
#[test]
fn an_unchanged_secret_the_state_did_not_see_so_is_given_again() {
    let (store, _, mut a, mut b) = setup();
    with_secrets(&mut a);
    a.sync(&store);
    b.sync(&store);
    let mut local = unread(&b);
    local.unchanged[0].edited_ms += 1;
    let wrong = local.unchanged[0].key.clone();
    let pulled = pull_from(&mut b, &store, &local);
    assert_eq!(pulled.report.local_deletes, 0);
    assert_eq!(
        pulled.changes.iter().map(Change::key).collect::<Vec<_>>(),
        [wrong]
    );
}

/// A secret a round brought that the app could not write (its keychain
/// locked by then) is named until written: it comes again, and its
/// deletion too, and nothing is deleted for it.
#[test]
fn a_secret_the_app_could_not_write_is_given_again() {
    let (store, _, mut a, mut b) = setup();
    let web = with_secrets(&mut a);
    a.sync(&store);
    b.sync(&store);
    let pw = key(Kind::SecretPassword, &web);
    b.app.remove(&pw);
    b.unreadable = vec![pw.clone()];

    let pulled = b.pull(&store).unwrap();
    assert_eq!(pulled.report.local_deletes, 0);
    assert!(pulled.changes.iter().any(|change| change.key() == pw));
    b.apply(&pulled);
    b.push(&store).unwrap();
    b.unreadable.clear();
    assert_eq!(
        value(&b, Kind::SecretPassword, &web).as_deref(),
        Some("pw-web")
    );
    let (report, _) = b.sync(&store);
    assert_eq!(report.local_deletes, 0);
    a.sync(&store);
    assert_eq!(a.data(), b.data());

    // Deleted elsewhere meanwhile: the deletion comes instead.
    b.app.remove(&pw);
    b.unreadable = vec![pw.clone()];
    a.wait(1000);
    a.remove(Kind::SecretPassword, &web);
    a.sync(&store);
    let pulled = b.pull(&store).unwrap();
    assert!(
        pulled
            .changes
            .iter()
            .any(|change| matches!(change, Change::Delete { .. }) && change.key() == pw)
    );
}

/// What the app cannot read and never synced is no deletion of the
/// round's.
#[test]
fn a_record_the_app_cannot_read_and_never_synced_is_left_alone() {
    let (store, _, mut a, _) = setup();
    a.put("c1", key_credential("deploy key"));
    a.unreadable = vec![key(Kind::SecretPrivateKey, "c1")];
    let pulled = a.pull(&store).unwrap();
    assert!(pulled.changes.is_empty(), "{:?}", pulled.changes);
}

/// Once a state's sealed secrets are lost, the files it read before are
/// read again: they hold what it lost.
#[test]
fn secrets_lost_from_the_state_come_back_from_unchanged_files() {
    let (store, _, mut a, mut b) = setup();
    let web = with_secrets(&mut a);
    a.sync(&store);
    b.sync(&store);
    // b's app forgets them too: only a's file has them now.
    b.app.retain(|key, _| !key.kind.is_secret());
    b.state.secrets = None;
    b.state.app_had.retain(|key| !key.kind.is_secret());
    b.state.edited_seen.retain(|key, _| !key.kind.is_secret());
    let sealed = a.state.secrets.clone().unwrap();
    b.state.secrets = Some(Sealed {
        sealed: vec![0; sealed.sealed.len()],
        ..sealed
    });
    b.sync(&store);
    assert_eq!(
        value(&b, Kind::SecretPassword, &web).as_deref(),
        Some("pw-web")
    );
}

#[test]
fn a_secret_of_a_later_version_is_passed_on_sealed() {
    let (store, keys, _, mut b) = setup();
    let c = plant(
        &store,
        &keys,
        'c',
        json!({"format": 1, "min_reader": 1, "device": {"id": "cccccccccccccccc"},
        "clock": [1, 0], "records": [
            {"kind": "secret.future", "id": "x1", "v": [1, 0, "cccccccccccccccc"],
             "data": {"value": "from-the-future"}}
        ]}),
    );
    let (report, _) = b.sync(&store);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(b.app.is_empty());
    assert!(!state_shows(&b, "from-the-future"));
    let file = read_file(&store, &keys, b.state.device());
    let future = key(Kind::Secret("secret.future".into()), "x1");
    assert_eq!(
        file.records[&future],
        read_file(&store, &keys, &c).records[&future]
    );
}

/// The digest of what was uploaded is kept in the app's database: a
/// secret's content must not go into it, or a weak password could be
/// guessed from it offline.
#[test]
fn the_upload_digest_leaves_secret_content_out() {
    let digest = |kind: Kind, value: &str| {
        let record = live(kind, "c1", version(1, 'a'), json!({"value": value}));
        let set = RecordSet::from([(record.key.clone(), record)]);
        records_digest(&DeviceInfo::default(), &set)
    };
    assert_eq!(
        digest(Kind::SecretCredential, "one"),
        digest(Kind::SecretCredential, "two")
    );
    assert_ne!(
        digest(Kind::Credential, "one"),
        digest(Kind::Credential, "two")
    );
}

#[test]
fn secrets_sealed_with_a_lost_key_come_back() {
    let (store, _, mut a, mut b) = setup();
    let web = with_secrets(&mut a);
    a.sync(&store);
    b.sync(&store);
    let sealed = b.state.secrets.clone().unwrap();
    b.state.secrets = Some(Sealed {
        sealed: vec![0; sealed.sealed.len()],
        ..sealed
    });
    let pulled = b.pull(&store).unwrap();
    assert!(pulled.report.warnings.contains(&Warning::SecretsUnreadable));
    assert_eq!(pulled.report.local_deletes, 0);
    b.apply(&pulled);
    b.push(&store).unwrap();
    assert_eq!(
        value(&b, Kind::SecretPassword, &web).as_deref(),
        Some("pw-web")
    );
    assert_eq!(b.data(), a.data());
}
