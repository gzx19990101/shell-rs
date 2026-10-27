//! Devices for tests: a fake app's records, the sync state it stores, its
//! clock and keys, driven the way the app will drive a round.

use std::collections::BTreeMap;

use crate::store::SyncStore;
use crate::wire::tests::ssh_host;
use crate::{
    Capabilities, Change, CredentialData, CredentialKind, DeviceId, DeviceInfo, EndpointSecret,
    Env, FixedEnv, GroupData, HostData, Keyring, Kind, LocalRecord, LocalSnapshot, Pulled, Pushed,
    RecordData, RecordKey, RoundOptions, RoundReport, Secret, SyncError, SyncState,
    endpoint_secret_id, pull, push,
};

pub(crate) struct Device {
    pub state: SyncState,
    pub env: FixedEnv,
    pub info: DeviceInfo,
    pub caps: Capabilities,
    pub keys: Keyring,
    /// The app's records and the time the user last edited each; its
    /// secrets among them, as if its keychain were part of it.
    pub app: BTreeMap<RecordKey, (RecordData, u64)>,
    /// Whether the keychain can be read: when not, a round goes without
    /// the app's secrets.
    pub keychain_ok: bool,
    /// Records the app cannot read for now.
    pub unreadable: Vec<RecordKey>,
}

impl Device {
    /// A device named after `name`, which also makes its id.
    pub fn new(name: char, keys: &Keyring, now_ms: u64) -> Self {
        Self {
            state: SyncState::new(DeviceId::parse(&name.to_string().repeat(16)).unwrap()),
            env: FixedEnv::new(now_ms, name as u64),
            info: DeviceInfo {
                name: format!("device {name}"),
                platform: "test".into(),
                app_version: "0.0.0".into(),
            },
            caps: Capabilities::ALL,
            keys: keys.clone(),
            app: BTreeMap::new(),
            keychain_ok: true,
            unreadable: Vec::new(),
        }
    }

    pub fn now(&self) -> u64 {
        self.env.now_ms()
    }

    pub fn wait(&mut self, ms: u64) {
        self.env.advance(ms);
    }

    /// The user saves `data` as record `id`.
    pub fn put(&mut self, id: &str, data: RecordData) {
        let key = RecordKey::new(data.kind(), id);
        let edited = self
            .app
            .get(&key)
            .map_or(self.now(), |(_, at)| self.now().max(at + 1));
        self.app.insert(key, (data, edited));
    }

    /// The user deletes the record.
    pub fn remove(&mut self, kind: Kind, id: &str) {
        self.app.remove(&RecordKey::new(kind, id));
    }

    pub fn get(&self, kind: Kind, id: &str) -> Option<&RecordData> {
        self.app
            .get(&RecordKey::new(kind, id))
            .map(|(data, _)| data)
    }

    pub fn data(&self) -> BTreeMap<RecordKey, RecordData> {
        self.app
            .iter()
            .map(|(key, (data, _))| (key.clone(), data.clone()))
            .collect()
    }

    /// What the app hands a round, as it would: its secrets only while its
    /// keychain opens.
    pub fn local(&self) -> LocalSnapshot {
        let secrets_read = self.keychain_ok;
        LocalSnapshot {
            records: self
                .app
                .iter()
                .filter(|(key, _)| secrets_read || !key.kind.is_secret())
                .filter(|(key, _)| !self.unreadable.contains(key))
                .map(|(key, (data, edited))| LocalRecord {
                    id: key.id.clone(),
                    data: data.clone(),
                    edited_ms: *edited,
                })
                .collect(),
            secrets_read,
            unreadable: self.unreadable.clone(),
            unchanged: Vec::new(),
        }
    }

    pub fn pull_with(
        &mut self,
        store: &dyn SyncStore,
        opts: RoundOptions,
    ) -> Result<Pulled, SyncError> {
        let local = self.local();
        pull(
            store,
            &self.keys,
            &self.state,
            &local,
            &self.caps,
            &opts,
            &mut self.env,
        )
    }

    pub fn pull(&mut self, store: &dyn SyncStore) -> Result<Pulled, SyncError> {
        self.pull_with(store, RoundOptions::default())
    }

    /// Take what a pull returned, as the app does: its changes and its
    /// state together. Records keep their edit time; new ones get 0.
    pub fn apply(&mut self, pulled: &Pulled) {
        for change in &pulled.changes {
            match change {
                Change::Upsert { id, data } => {
                    let key = RecordKey::new(data.kind(), id.clone());
                    let edited = self.app.get(&key).map_or(0, |(_, at)| *at);
                    self.app.insert(key, (data.clone(), edited));
                }
                Change::Delete { kind, id } => {
                    self.app.remove(&RecordKey::new(kind.clone(), id.clone()));
                }
            }
        }
        self.state = pulled.state.clone();
        if let Some(keys) = &pulled.keyring {
            self.keys = keys.clone();
        }
    }

    pub fn push(&mut self, store: &dyn SyncStore) -> Result<Pushed, SyncError> {
        let pushed = push(store, &self.keys, &self.info, &self.state, &mut self.env)?;
        if let Pushed::Uploaded { state } = &pushed {
            self.state = state.clone();
        }
        Ok(pushed)
    }

    /// A whole round: pull, apply, push.
    pub fn sync(&mut self, store: &dyn SyncStore) -> (RoundReport, Pushed) {
        let pulled = self.pull(store).expect("pull");
        self.apply(&pulled);
        let pushed = self.push(store).expect("push");
        (pulled.report, pushed)
    }
}

pub(crate) fn group(name: &str, parent: Option<&str>) -> RecordData {
    RecordData::Group(GroupData {
        name: name.into(),
        parent: parent.map(Into::into),
        sort_order: 0,
    })
}

pub(crate) fn host(name: &str, group: Option<&str>) -> RecordData {
    RecordData::Host(HostData {
        group: group.map(Into::into),
        ..ssh_host(name)
    })
}

pub(crate) fn credential(name: &str) -> RecordData {
    RecordData::Credential(CredentialData {
        name: name.into(),
        kind: CredentialKind::Password,
        username: "deploy".into(),
        sort_order: 0,
    })
}

pub(crate) fn key_credential(name: &str) -> RecordData {
    RecordData::Credential(CredentialData {
        kind: CredentialKind::Key,
        ..match credential(name) {
            RecordData::Credential(data) => data,
            _ => unreachable!(),
        }
    })
}

/// The saved password of `user` at `host:22`, with its record's id.
pub(crate) fn password(user: &str, host: &str, value: &str) -> (String, RecordData) {
    (
        endpoint_secret_id(user, host, 22),
        RecordData::Password(EndpointSecret {
            user: user.into(),
            host: host.into(),
            port: 22,
            value: Secret::new(value),
        }),
    )
}
