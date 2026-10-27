//! A snapshot: every record a device knows, as compressed JSON.
//!
//! ```json
//! {"format": 1, "min_reader": 1,
//!  "device": {"id": "…", "name": "MacBook Pro", "platform": "macos", "app": "0.2.0"},
//!  "clock": [ms, counter], "purged_before": 0,
//!  "records": [{"kind": "host", "id": "…", "v": [ms, counter, "device"], "data": {…}}, …]}
//! ```
//!
//! `min_reader` is the oldest format that can read the file; an older
//! reader leaves the file out and stops writing until updated.
//! `purged_before` is reserved for removing old deletions, which this
//! format never does.

use std::io::{Read as _, Write as _};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use serde_json::{Value, json};

use crate::merge::join;
use crate::record::{RawRecord, RecordSet};
use crate::{DeviceId, FORMAT, Stamp};

/// The largest device file read, and the most its JSON may inflate to: a
/// file past either is damaged or hostile.
pub(crate) const MAX_FILE: u64 = 16 << 20;
const MAX_JSON: u64 = 64 << 20;

/// What a device says of itself in its file, for the others' device lists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    pub name: String,
    /// `macos`, `windows`, `linux`, `ios`, `android`.
    pub platform: String,
    pub app_version: String,
}

#[derive(Debug)]
pub(crate) struct Snapshot {
    pub info: DeviceInfo,
    pub clock: Stamp,
    pub records: RecordSet,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    Corrupt(String),
    TooNew(u32),
}

pub(crate) fn encode(
    device: &DeviceId,
    info: &DeviceInfo,
    clock: Stamp,
    records: &RecordSet,
) -> Vec<u8> {
    let snapshot = json!({
        "format": FORMAT,
        "min_reader": 1,
        "device": {
            "id": device.as_str(),
            "name": info.name,
            "platform": info.platform,
            "app": info.app_version,
        },
        "clock": [clock.ms, clock.counter],
        "purged_before": 0,
        "records": records.values().map(RawRecord::to_json).collect::<Vec<_>>(),
    });
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&serde_json::to_vec(&snapshot).expect("a snapshot serializes"))
        .expect("writing to memory");
    encoder.finish().expect("writing to memory")
}

/// The snapshot in `bytes`, which must be `device`'s.
pub(crate) fn decode(bytes: &[u8], device: &DeviceId) -> Result<Snapshot, DecodeError> {
    let corrupt = |why: &str| DecodeError::Corrupt(why.to_owned());
    let mut json = Vec::new();
    DeflateDecoder::new(bytes)
        .take(MAX_JSON + 1)
        .read_to_end(&mut json)
        .map_err(|_| corrupt("not compressed as expected"))?;
    if json.len() as u64 > MAX_JSON {
        return Err(corrupt("too large"));
    }
    let snapshot: Value = serde_json::from_slice(&json).map_err(|_| corrupt("not JSON"))?;
    let number = |key: &str| snapshot.get(key).and_then(Value::as_u64);
    let min_reader = number("min_reader").ok_or_else(|| corrupt("no min_reader"))?;
    if min_reader > u64::from(FORMAT) {
        return Err(DecodeError::TooNew(
            u32::try_from(min_reader).unwrap_or(u32::MAX),
        ));
    }
    number("format").ok_or_else(|| corrupt("no format"))?;
    let header = snapshot.get("device").ok_or_else(|| corrupt("no device"))?;
    let text = |key: &str| {
        header
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| corrupt("no device description"))
    };
    if header.get("id").and_then(Value::as_str) != Some(device.as_str()) {
        return Err(corrupt("another device's file"));
    }
    let clock = match snapshot
        .get("clock")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([ms, counter]) => Stamp {
            ms: ms.as_u64().ok_or_else(|| corrupt("bad clock"))?,
            counter: counter
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| corrupt("bad clock"))?,
        },
        _ => return Err(corrupt("no clock")),
    };
    if !clock.is_sane() {
        return Err(corrupt("a clock past any date"));
    }
    let mut records = RecordSet::new();
    for value in snapshot
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| corrupt("no records"))?
    {
        join(
            &mut records,
            RawRecord::from_json(value).map_err(DecodeError::Corrupt)?,
        );
    }
    Ok(Snapshot {
        info: DeviceInfo {
            name: text("name")?,
            platform: text("platform")?,
            app_version: text("app")?,
        },
        clock,
        records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kind;
    use crate::record::tests::{deleted, device, live, version};

    fn deflate(json: &Value) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&serde_json::to_vec(json).unwrap())
            .unwrap();
        encoder.finish().unwrap()
    }

    /// A file's description of the device `id`.
    fn described(id: &DeviceId) -> Value {
        json!({"id": id.as_str(), "name": "Mac", "platform": "macos", "app": "0.2.0"})
    }

    fn info() -> DeviceInfo {
        DeviceInfo {
            name: "Mac".into(),
            platform: "macos".into(),
            app_version: "0.2.0".into(),
        }
    }

    #[test]
    fn a_snapshot_reads_back_with_what_this_version_does_not_know() {
        let mut records = RecordSet::new();
        let mut host = live(
            Kind::Host,
            "h",
            version(5, 'a'),
            json!({"name": "web", "future": 1}),
        );
        host.rest.insert("signed".into(), json!(true));
        join(&mut records, host);
        join(
            &mut records,
            live(
                Kind::Other("tag".into()),
                "t",
                version(6, 'b'),
                json!({"x": 1}),
            ),
        );
        join(&mut records, deleted(Kind::Group, "g", version(7, 'a')));
        let me = device('a');
        let bytes = encode(&me, &info(), Stamp { ms: 9, counter: 2 }, &records);
        let back = decode(&bytes, &me).unwrap();
        assert_eq!(back.records, records);
        assert_eq!(back.info, info());
        assert_eq!(back.clock, Stamp { ms: 9, counter: 2 });
        assert_eq!(
            decode(&bytes, &device('b')).unwrap_err(),
            DecodeError::Corrupt("another device's file".into())
        );
    }

    /// Secrets travel in the file, which is encrypted whole; one of a kind
    /// this version does not know travels on as it came.
    #[test]
    fn secrets_travel_in_the_file() {
        let mut records = RecordSet::new();
        for kind in [Kind::SecretCredential, Kind::Secret("secret.future".into())] {
            join(
                &mut records,
                live(kind, "s", version(1, 'a'), json!({"value": "x"})),
            );
        }
        let me = device('a');
        let bytes = encode(&me, &info(), Stamp::default(), &records);
        assert_eq!(decode(&bytes, &me).unwrap().records, records);
    }

    #[test]
    fn a_newer_reader_is_asked_for() {
        let me = device('a');
        let file = json!({"format": 3, "min_reader": 2, "device": described(&me),
            "clock": [1, 0], "records": []});
        assert_eq!(
            decode(&deflate(&file), &me).unwrap_err(),
            DecodeError::TooNew(2)
        );
        let file = json!({"format": 3, "min_reader": 1, "device": described(&me),
            "clock": [1, 0], "records": [], "new_thing": {}});
        assert!(decode(&deflate(&file), &me).is_ok());
    }

    #[test]
    fn the_same_record_twice_keeps_the_later() {
        let me = device('a');
        let file = json!({"format": 1, "min_reader": 1, "device": described(&me),
        "clock": [1, 0], "records": [
            {"kind": "group", "id": "g", "v": [2, 0, me.as_str()], "data": {"name": "new"}},
            {"kind": "group", "id": "g", "v": [1, 0, me.as_str()], "data": {"name": "old"}}
        ]});
        let records = decode(&deflate(&file), &me).unwrap().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records.values().next().unwrap().version.stamp.ms, 2);
    }

    #[test]
    fn damaged_files_are_refused() {
        let me = device('a');
        let corrupt = |file: Value| decode(&deflate(&file), &me).is_err();
        assert!(corrupt(
            json!({"min_reader": 1, "device": described(&me), "clock": [1, 0], "records": []})
        ));
        assert!(corrupt(
            json!({"format": 1, "min_reader": 1, "device": described(&me),
            "clock": [1u64 << 50, 0], "records": []})
        ));
        assert!(corrupt(
            json!({"format": 1, "min_reader": 1, "device": described(&me),
            "clock": [1, 0], "records": [{"kind": "group"}]})
        ));
        assert!(corrupt(
            json!({"format": 1, "min_reader": 1, "device": {"id": me.as_str()},
            "clock": [1, 0], "records": []})
        ));
        assert!(decode(b"not deflate at all", &me).is_err());
        // A gigabyte of zeros compresses to a megabyte: it is cut off at
        // the limit, not inflated whole.
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..80 {
            encoder.write_all(&zeros).unwrap();
        }
        let bomb = encoder.finish().unwrap();
        assert_eq!(
            decode(&bomb, &me).unwrap_err(),
            DecodeError::Corrupt("too large".into())
        );
    }
}
