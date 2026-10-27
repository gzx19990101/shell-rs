//! Records as they travel: kept as the JSON they came in, so fields and
//! kinds a newer ShellRS added survive this one untouched. The typed view
//! the app sees is `wire`'s.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{DeviceId, Kind, RecordKey, Stamp, Version};

pub(crate) type Map = serde_json::Map<String, Value>;

/// What a record holds: its fields, or nothing but the fact it was deleted
/// (a tombstone, kept so the deletion wins over older copies).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Body {
    Live(Map),
    Deleted,
}

/// One copy of a record. Its `Debug` leaves out a secret's fields.
#[derive(Clone, PartialEq)]
pub(crate) struct RawRecord {
    pub key: RecordKey,
    pub version: Version,
    pub body: Body,
    /// The oldest format that can use this record; one this version cannot
    /// use is kept and passed on but never given to the app.
    pub min_reader: Option<u32>,
    /// Record-level fields this version does not know, passed on as they
    /// came.
    pub rest: Map,
}

pub(crate) type RecordSet = BTreeMap<RecordKey, RawRecord>;

impl fmt::Debug for RawRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("RawRecord");
        out.field("key", &self.key).field("version", &self.version);
        match &self.body {
            Body::Live(_) if self.key.kind.is_secret() => out.field("body", &"Live(…)"),
            body => out.field("body", body),
        };
        out.field("min_reader", &self.min_reader)
            .field("rest", &self.rest)
            .finish()
    }
}

impl RawRecord {
    pub(crate) fn live(&self) -> Option<&Map> {
        match &self.body {
            Body::Live(data) => Some(data),
            Body::Deleted => None,
        }
    }

    pub(crate) fn is_deleted(&self) -> bool {
        matches!(self.body, Body::Deleted)
    }

    /// The record as written in a snapshot:
    /// `{"kind", "id", "v": [ms, counter, device], "data": {…}}`, or
    /// `"deleted": true` in place of `data`.
    pub(crate) fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("kind".into(), json!(self.key.kind.as_str()));
        out.insert("id".into(), json!(self.key.id));
        out.insert(
            "v".into(),
            json!([
                self.version.stamp.ms,
                self.version.stamp.counter,
                self.version.device.as_str()
            ]),
        );
        match &self.body {
            Body::Live(data) => out.insert("data".into(), Value::Object(data.clone())),
            Body::Deleted => out.insert("deleted".into(), json!(true)),
        };
        if let Some(min_reader) = self.min_reader {
            out.insert("min_reader".into(), json!(min_reader));
        }
        for (key, value) in &self.rest {
            out.entry(key.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(out)
    }

    pub(crate) fn from_json(value: &Value) -> Result<Self, String> {
        let Value::Object(fields) = value else {
            return Err("a record is not an object".into());
        };
        let kind = fields
            .get("kind")
            .and_then(Value::as_str)
            .and_then(Kind::parse)
            .ok_or("a record has no valid kind")?;
        let id = fields
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| RecordKey::is_valid_id(id))
            .ok_or("a record has no valid id")?;
        let version = parse_version(fields.get("v")).ok_or("a record has no valid version")?;
        let body = match (fields.get("data"), fields.get("deleted")) {
            (Some(Value::Object(data)), None) => Body::Live(data.clone()),
            (None, Some(Value::Bool(true))) => Body::Deleted,
            _ => return Err(format!("record {} has no data", id)),
        };
        let min_reader = match fields.get("min_reader") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("a record's min_reader is not a number")?,
            ),
        };
        let rest = fields
            .iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "kind" | "id" | "v" | "data" | "deleted" | "min_reader"
                )
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Ok(Self {
            key: RecordKey::new(kind, id),
            version,
            body,
            min_reader,
            rest,
        })
    }

    /// What decides between two copies with the same version: a hash of the
    /// record as written. The same copy hashes the same on every device,
    /// since records keep the fields and order they came with.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(&self.to_json()).unwrap_or_default();
        Sha256::digest(bytes).into()
    }
}

fn parse_version(value: Option<&Value>) -> Option<Version> {
    let [ms, counter, device] = value?.as_array()?.as_slice() else {
        return None;
    };
    let stamp = Stamp {
        ms: ms.as_u64()?,
        counter: u32::try_from(counter.as_u64()?).ok()?,
    };
    stamp.is_sane().then_some(())?;
    Some(Version {
        stamp,
        device: DeviceId::parse(device.as_str()?)?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn device(name: char) -> DeviceId {
        DeviceId::parse(&name.to_string().repeat(16)).unwrap()
    }

    pub(crate) fn version(ms: u64, by: char) -> Version {
        Version {
            stamp: Stamp { ms, counter: 0 },
            device: device(by),
        }
    }

    pub(crate) fn live(kind: Kind, id: &str, at: Version, data: Value) -> RawRecord {
        let Value::Object(data) = data else {
            panic!("data must be an object")
        };
        RawRecord {
            key: RecordKey::new(kind, id),
            version: at,
            body: Body::Live(data),
            min_reader: None,
            rest: Map::new(),
        }
    }

    pub(crate) fn deleted(kind: Kind, id: &str, at: Version) -> RawRecord {
        RawRecord {
            key: RecordKey::new(kind, id),
            version: at,
            body: Body::Deleted,
            min_reader: None,
            rest: Map::new(),
        }
    }

    #[test]
    fn records_read_back_with_what_this_version_does_not_know() {
        let value = json!({
            "kind": "host", "id": "h1", "v": [5, 1, "aaaaaaaaaaaaaaaa"],
            "data": {"name": "web", "future": [1, 2]},
            "min_reader": 1, "signed_by": "someone"
        });
        let record = RawRecord::from_json(&value).unwrap();
        assert_eq!(record.key, RecordKey::new(Kind::Host, "h1"));
        assert_eq!(record.version.stamp, Stamp { ms: 5, counter: 1 });
        assert_eq!(record.rest.get("signed_by"), Some(&json!("someone")));
        assert_eq!(record.to_json(), value);

        let tombstone =
            json!({"kind": "tag", "id": "t", "v": [1, 0, "aaaaaaaaaaaaaaaa"], "deleted": true});
        let record = RawRecord::from_json(&tombstone).unwrap();
        assert!(record.is_deleted());
        assert_eq!(record.key.kind, Kind::Other("tag".into()));
        assert_eq!(record.to_json(), tombstone);
    }

    #[test]
    fn a_secret_record_shows_no_fields() {
        let secret = live(
            Kind::SecretCredential,
            "c1",
            version(1, 'a'),
            json!({"value": "hunter2"}),
        );
        let shown = format!("{secret:?}");
        assert!(
            !shown.contains("hunter2") && shown.contains("c1"),
            "{shown}"
        );
        let host = live(Kind::Host, "h", version(1, 'a'), json!({"name": "web"}));
        assert!(format!("{host:?}").contains("web"));
    }

    #[test]
    fn malformed_records_are_refused() {
        for value in [
            json!([]),
            json!({"kind": "host", "id": "h", "v": [1, 0, "aaaaaaaaaaaaaaaa"]}),
            json!({"kind": "host", "id": "h", "v": [1, 0, "aaaaaaaaaaaaaaaa"], "data": {}, "deleted": true}),
            json!({"kind": "host", "id": "h", "v": [1, 0, "aaaaaaaaaaaaaaaa"], "deleted": false}),
            json!({"kind": "host", "id": "h/1", "v": [1, 0, "aaaaaaaaaaaaaaaa"], "data": {}}),
            json!({"kind": "Host", "id": "h", "v": [1, 0, "aaaaaaaaaaaaaaaa"], "data": {}}),
            json!({"kind": "host", "id": "h", "v": [1, 0, "AAAA"], "data": {}}),
            json!({"kind": "host", "id": "h", "v": [1u64 << 48, 0, "aaaaaaaaaaaaaaaa"], "data": {}}),
            json!({"kind": "host", "id": "h", "v": [1, -1, "aaaaaaaaaaaaaaaa"], "data": {}}),
            json!({"kind": "host", "id": "h", "v": [1, 0], "data": {}}),
        ] {
            assert!(RawRecord::from_json(&value).is_err(), "{value}");
        }
    }
}
