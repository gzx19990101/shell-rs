//! What a device keeps between rounds, as one blob the app stores: every
//! record with its version, what the app was last given and when, and the
//! tags of the files already read. Secrets are in it only sealed with the
//! vault's data key (`secret::seal`): the blob shows none in the clear.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::record::{RawRecord, RecordSet};
use crate::secret::Sealed;
use crate::snapshot::DeviceInfo;
use crate::{DeviceId, Kind, RecordKey, Stamp, SyncError, hex};

const STATE_FORMAT: u64 = 1;

/// A device's sync state. Begin with `new` when the device first syncs a
/// vault; thereafter store what `pull` and `push` return, and only that.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncState {
    pub(crate) device: DeviceId,
    pub(crate) clock: Stamp,
    /// Every record this device knows, deletions included, but secrets.
    pub(crate) records: RecordSet,
    /// The secret records, sealed; `None` when there are none.
    pub(crate) secrets: Option<Sealed>,
    /// The records the app holds after the last round: one gone from it
    /// since was deleted there.
    pub(crate) app_had: BTreeSet<RecordKey>,
    /// Each record's edit time as the app had it when last given the record
    /// or when its edit was taken: a different one is a new edit.
    pub(crate) edited_seen: BTreeMap<RecordKey, u64>,
    /// The other devices' files as last read.
    pub(crate) files: BTreeMap<DeviceId, FileMemo>,
    /// This device's file as last written.
    pub(crate) own: Option<OwnMemo>,
    /// Set while some file needs a newer format: the device must not write.
    pub(crate) read_only: Option<u32>,
    pub(crate) joined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileMemo {
    pub etag: String,
    pub info: DeviceInfo,
    pub clock_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnMemo {
    pub etag: String,
    /// What was written: the device's description and its records.
    pub digest: String,
    pub generation: u32,
}

impl SyncState {
    pub fn new(device: DeviceId) -> Self {
        Self {
            device,
            clock: Stamp::default(),
            records: RecordSet::new(),
            secrets: None,
            app_had: BTreeSet::new(),
            edited_seen: BTreeMap::new(),
            files: BTreeMap::new(),
            own: None,
            read_only: None,
            joined: false,
        }
    }

    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    /// The edit time the last round saw for record `key`, when it saw it:
    /// a record of the app with this time is unchanged since, and need not
    /// be read again (`LocalSnapshot::unchanged`).
    pub fn edit_seen(&self, key: &RecordKey) -> Option<u64> {
        self.edited_seen.get(key).copied()
    }

    /// Whether this device has not synced yet: its first round decides
    /// whether its records join the others' or give way to them
    /// (`RoundOptions::join`).
    pub fn is_fresh(&self) -> bool {
        !self.joined
    }

    /// The same state under a new device id, for when another device turns
    /// out to share this one's (a copied portable data folder): the old
    /// file is the other's from now on.
    pub fn with_device(self, device: DeviceId) -> Self {
        Self {
            device,
            own: None,
            ..self
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let key = |key: &RecordKey| json!([key.kind.as_str(), key.id]);
        let state = json!({
            "state_format": STATE_FORMAT,
            "device": self.device.as_str(),
            "clock": [self.clock.ms, self.clock.counter],
            "joined": self.joined,
            "read_only": self.read_only,
            "records": self.records.values().map(RawRecord::to_json).collect::<Vec<_>>(),
            "secrets": self.secrets.as_ref().map(|sealed| json!({
                "generation": sealed.generation,
                "nonce": hex::encode(&sealed.nonce),
                "sealed": hex::encode(&sealed.sealed),
            })),
            "app_had": self.app_had.iter().map(key).collect::<Vec<_>>(),
            "edited_seen": self.edited_seen.iter()
                .map(|(record, at)| json!([record.kind.as_str(), record.id, at]))
                .collect::<Vec<_>>(),
            "files": self.files.iter()
                .map(|(device, memo)| (device.to_string(), json!({
                    "etag": memo.etag,
                    "name": memo.info.name,
                    "platform": memo.info.platform,
                    "app": memo.info.app_version,
                    "clock_ms": memo.clock_ms,
                })))
                .collect::<serde_json::Map<_, _>>(),
            "own": self.own.as_ref().map(|own| json!({
                "etag": own.etag,
                "digest": own.digest,
                "generation": own.generation,
            })),
        });
        serde_json::to_vec(&state).expect("a state serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SyncError> {
        let bad = |why: &str| SyncError::StateUnreadable(why.to_owned());
        let state: Value = serde_json::from_slice(bytes).map_err(|_| bad("not JSON"))?;
        if state.get("state_format").and_then(Value::as_u64) != Some(STATE_FORMAT) {
            return Err(bad("unknown state format"));
        }
        let text = |value: &Value, key: &str| -> Result<String, SyncError> {
            Ok(value
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| bad(key))?
                .to_owned())
        };
        let device = DeviceId::parse(&text(&state, "device")?).ok_or_else(|| bad("device"))?;
        let clock = match state
            .get("clock")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
        {
            Some([ms, counter]) => Stamp {
                ms: ms.as_u64().ok_or_else(|| bad("clock"))?,
                counter: counter
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| bad("clock"))?,
            },
            _ => return Err(bad("clock")),
        };
        let list = |key: &str| {
            state
                .get(key)
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| bad(key))
        };
        let mut records = RecordSet::new();
        for value in list("records")? {
            let record = RawRecord::from_json(&value).map_err(|why| bad(&why))?;
            // Never one: secrets are sealed apart, and one in the clear is
            // not taken even if a bug put it there.
            if !record.key.kind.is_secret() {
                records.insert(record.key.clone(), record);
            }
        }
        let secrets = match state.get("secrets").ok_or_else(|| bad("secrets"))? {
            Value::Null => None,
            sealed => Some(Sealed {
                generation: sealed
                    .get("generation")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| bad("secrets"))?,
                nonce: hex::decode_array(&text(sealed, "nonce")?).ok_or_else(|| bad("secrets"))?,
                sealed: hex::decode(&text(sealed, "sealed")?).ok_or_else(|| bad("secrets"))?,
            }),
        };
        let record_key = |value: &Value| -> Result<RecordKey, SyncError> {
            let kind = value
                .get(0)
                .and_then(Value::as_str)
                .and_then(Kind::parse)
                .ok_or_else(|| bad("a record key"))?;
            let id = value
                .get(1)
                .and_then(Value::as_str)
                .ok_or_else(|| bad("a record key"))?;
            Ok(RecordKey::new(kind, id))
        };
        let app_had = list("app_had")?
            .iter()
            .map(record_key)
            .collect::<Result<_, _>>()?;
        let edited_seen = list("edited_seen")?
            .iter()
            .map(|value| {
                let at = value
                    .get(2)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| bad("a time"))?;
                Ok((record_key(value)?, at))
            })
            .collect::<Result<_, SyncError>>()?;
        let mut files = BTreeMap::new();
        for (device, memo) in state
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| bad("files"))?
        {
            files.insert(
                DeviceId::parse(device).ok_or_else(|| bad("a device"))?,
                FileMemo {
                    etag: text(memo, "etag")?,
                    info: DeviceInfo {
                        name: text(memo, "name")?,
                        platform: text(memo, "platform")?,
                        app_version: text(memo, "app")?,
                    },
                    clock_ms: memo
                        .get("clock_ms")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| bad("clock_ms"))?,
                },
            );
        }
        let own = match state.get("own").ok_or_else(|| bad("own"))? {
            Value::Null => None,
            own => Some(OwnMemo {
                etag: text(own, "etag")?,
                digest: text(own, "digest")?,
                generation: own
                    .get("generation")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| bad("generation"))?,
            }),
        };
        Ok(Self {
            device,
            clock,
            records,
            secrets,
            app_had,
            edited_seen,
            files,
            own,
            read_only: match state.get("read_only").ok_or_else(|| bad("read_only"))? {
                Value::Null => None,
                n => Some(
                    n.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| bad("read_only"))?,
                ),
            },
            joined: state
                .get("joined")
                .and_then(Value::as_bool)
                .ok_or_else(|| bad("joined"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests::{deleted, device, live, version};

    #[test]
    fn a_state_reads_back() {
        let mut state = SyncState::new(device('a'));
        state.clock = Stamp { ms: 9, counter: 1 };
        let host = live(Kind::Host, "h", version(5, 'b'), json!({"name": "web"}));
        state.records.insert(host.key.clone(), host.clone());
        let group = deleted(Kind::Group, "g", version(6, 'a'));
        state.records.insert(group.key.clone(), group);
        state.app_had.insert(host.key.clone());
        state.edited_seen.insert(host.key.clone(), 77);
        state.files.insert(
            device('b'),
            FileMemo {
                etag: "t3".into(),
                info: DeviceInfo {
                    name: "phone".into(),
                    platform: "ios".into(),
                    app_version: "1.0".into(),
                },
                clock_ms: 5,
            },
        );
        state.own = Some(OwnMemo {
            etag: "t4".into(),
            digest: "abc".into(),
            generation: 2,
        });
        state.read_only = Some(2);
        state.joined = true;
        state.secrets = Some(Sealed {
            generation: 3,
            nonce: [7; 24],
            sealed: vec![1, 2, 3],
        });
        assert_eq!(SyncState::from_bytes(&state.to_bytes()).unwrap(), state);
        assert!(!state.is_fresh());
        assert!(SyncState::new(device('a')).is_fresh());
    }

    #[test]
    fn an_unknown_state_is_not_guessed_at() {
        let mut bytes: Value =
            serde_json::from_slice(&SyncState::new(device('a')).to_bytes()).unwrap();
        bytes["state_format"] = 2.into();
        assert!(SyncState::from_bytes(&serde_json::to_vec(&bytes).unwrap()).is_err());
        assert!(SyncState::from_bytes(b"{").is_err());
    }

    #[test]
    fn a_new_device_id_forgets_its_own_file() {
        let mut state = SyncState::new(device('a'));
        state.own = Some(OwnMemo {
            etag: "t".into(),
            digest: "d".into(),
            generation: 1,
        });
        let moved = state.with_device(device('c'));
        assert_eq!(moved.device(), &device('c'));
        assert_eq!(moved.own, None);
    }
}
