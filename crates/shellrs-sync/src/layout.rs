//! Where things are in a store, relative to the root the user chose (a
//! WebDAV folder, a bucket and prefix, a local folder):
//!
//! ```text
//! shellrs-sync/v1/vault.json            the keys, wrapped by the sync password
//! shellrs-sync/v1/devices/<id>.srs      one device's encrypted snapshot
//! ```
//!
//! These names never change once released.

use crate::DeviceId;

pub const VAULT: &str = "shellrs-sync/v1/vault.json";
pub const DEVICES: &str = "shellrs-sync/v1/devices";

/// The path of a device's file.
pub fn device_file(device: &DeviceId) -> String {
    format!("{DEVICES}/{device}.srs")
}

/// The device whose file `name` is (a name within `DEVICES`), or `None`
/// for anything else there: a cloud drive's conflicted copy (`x (1).srs`),
/// a placeholder (`.x.srs.icloud`), a temporary file.
pub fn device_of(name: &str) -> Option<DeviceId> {
    DeviceId::parse(name.strip_suffix(".srs")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_device_files_name_a_device() {
        let id = "k3jq8x0m2pa7d4vn";
        assert_eq!(
            device_of(&format!("{id}.srs")).map(|d| d.to_string()),
            Some(id.to_owned())
        );
        for other in [
            format!("{id} (1).srs"),
            format!("{id} 2.srs"),
            format!("{id} (conflicted copy 2026-10-25).srs"),
            format!(".{id}.srs.icloud"),
            format!("{id}.srs.tmp"),
            format!(".{id}.srs.4f2a.tmp"),
            "K3JQ8X0M2PA7D4VN.srs".to_owned(),
            format!("{id}a.srs"),
            "vault.json".to_owned(),
        ] {
            assert_eq!(device_of(&other), None, "{other}");
        }
        let device = DeviceId::parse(id).unwrap();
        assert_eq!(
            device_file(&device),
            format!("shellrs-sync/v1/devices/{id}.srs")
        );
    }
}
