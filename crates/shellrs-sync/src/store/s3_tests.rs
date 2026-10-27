//! The S3 store: its signatures against AWS's own example, what services
//! answer, read without one; then the store against a real one (the
//! `service` tests, ignored by default), named by `SHELLRS_TEST_S3_*`, as
//! CI names a versitygw it starts.

use super::*;

const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/// AWS's example of a presigned GET: the same canonical request and key
/// derivation as a signed header, the query in its place.
#[test]
fn signatures_are_aws_examples() {
    let mut query: Vec<(String, String)> = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        (
            "X-Amz-Credential",
            "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
        ),
        ("X-Amz-Date", "20130524T000000Z"),
        ("X-Amz-Expires", "86400"),
        ("X-Amz-SignedHeaders", "host"),
    ]
    .into_iter()
    .map(|(name, value)| (uri_encode(name, true), uri_encode(value, true)))
    .collect();
    query.sort();
    let query = query
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical = canonical_request(
        "GET",
        "/test.txt",
        &query,
        &[("host", "examplebucket.s3.amazonaws.com")],
        "UNSIGNED-PAYLOAD",
    );
    assert_eq!(
        signature(AWS_SECRET, "20130524T000000Z", "us-east-1", &canonical),
        "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
}

/// AWS's example of a GET signed in its headers, a range among them.
#[test]
fn header_signatures_are_aws_examples() {
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(hex::encode(&Sha256::digest(b"")), empty);
    let canonical = canonical_request(
        "GET",
        "/test.txt",
        "",
        &[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", empty),
            ("x-amz-date", "20130524T000000Z"),
        ],
        empty,
    );
    assert_eq!(
        signature(AWS_SECRET, "20130524T000000Z", "us-east-1", &canonical),
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
}

#[test]
fn request_times_read_as_aws_writes_them() {
    assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
    assert_eq!(amz_date(1_709_251_199), "20240229T235959Z");
    assert_eq!(amz_date(0), "19700101T000000Z");
}

#[test]
fn keys_are_encoded_once_and_slashes_kept_in_paths() {
    assert_eq!(uri_encode("a b/ç~-_.", false), "a%20b/%C3%A7~-_.");
    assert_eq!(uri_encode("a/b", true), "a%2Fb");
    assert_eq!(uri_encode("x+y=z", true), "x%2By%3Dz");
}

fn location(endpoint: &str, prefix: &str, path_style: bool) -> S3Location {
    S3Location {
        endpoint: endpoint.into(),
        region: String::new(),
        bucket: "my-bucket".into(),
        prefix: prefix.into(),
        path_style,
    }
}

#[test]
fn a_bucket_is_reached_by_its_host_or_its_path() {
    let virtual_hosted = S3Store::new(
        &location("https://s3.us-east-1.amazonaws.com", "/ShellRS/", false),
        "key",
        "secret",
        "test",
    )
    .unwrap();
    let key = virtual_hosted.key("shellrs-sync/v1/vault.json").unwrap();
    assert_eq!(key, "ShellRS/shellrs-sync/v1/vault.json");
    assert_eq!(
        virtual_hosted.host_and_path(Some(&key)),
        (
            "my-bucket.s3.us-east-1.amazonaws.com".into(),
            "/ShellRS/shellrs-sync/v1/vault.json".into()
        )
    );
    assert_eq!(
        virtual_hosted.host_and_path(None),
        ("my-bucket.s3.us-east-1.amazonaws.com".into(), "/".into())
    );
    assert_eq!(virtual_hosted.region, "us-east-1");

    let path_style = S3Store::new(
        &location("http://127.0.0.1:9000", "", true),
        "key",
        "secret",
        "test",
    )
    .unwrap();
    let key = path_style.key("a b.srs").unwrap();
    assert_eq!(
        path_style.host_and_path(Some(&key)),
        ("127.0.0.1:9000".into(), "/my-bucket/a%20b.srs".into())
    );
    assert_eq!(
        path_style.host_and_path(None),
        ("127.0.0.1:9000".into(), "/my-bucket".into())
    );
    assert!(path_style.key("../x").is_err());
    assert!(!format!("{path_style:?}").contains("secret"));

    for (endpoint, bucket) in [
        ("ftp://x.example", "b"),
        ("x.example", "b"),
        ("https://x.example", ""),
        ("https://x.example", "a/b"),
    ] {
        let location = S3Location {
            bucket: bucket.into(),
            ..location(endpoint, "", false)
        };
        assert!(
            S3Store::new(&location, "k", "s", "t").is_err(),
            "{endpoint} {bucket}"
        );
    }
}

const LISTING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix>ShellRS/shellrs-sync/v1/devices/</Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>true</IsTruncated>
  <Contents>
    <Key>ShellRS/shellrs-sync/v1/devices/aaaaaaaaaaaaaaaa.srs</Key>
    <LastModified>2026-10-25T10:00:00.000Z</LastModified>
    <ETag>&quot;9b2cf535f27731c974343645a3985328&quot;</ETag>
    <Size>1234</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>ShellRS/shellrs-sync/v1/devices/bbbbbbbbbbbbbbbb.srs</Key>
    <ETag>"d41d8cd98f00b204e9800998ecf8427e-2"</ETag>
    <Size>99</Size>
  </Contents>
  <CommonPrefixes><Prefix>ShellRS/shellrs-sync/v1/devices/old/</Prefix></CommonPrefixes>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
</ListBucketResult>"#;

#[test]
fn listings_read_with_their_etags_and_next_page() {
    let listing = parse_listing(LISTING.as_bytes()).unwrap();
    assert_eq!(
        listing.objects,
        [
            Object {
                key: "ShellRS/shellrs-sync/v1/devices/aaaaaaaaaaaaaaaa.srs".into(),
                etag: r#""9b2cf535f27731c974343645a3985328""#.into(),
                size: 1234,
            },
            Object {
                key: "ShellRS/shellrs-sync/v1/devices/bbbbbbbbbbbbbbbb.srs".into(),
                etag: r#""d41d8cd98f00b204e9800998ecf8427e-2""#.into(),
                size: 99,
            },
        ]
    );
    assert!(listing.truncated);
    assert_eq!(
        listing.next.as_deref(),
        Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=")
    );
    // An ETag goes back as it came.
    let tag = etag_tag(&listing.objects[0].etag);
    assert_eq!(
        etag_of(&tag).as_deref(),
        Some(listing.objects[0].etag.as_str())
    );
}

#[test]
fn refusals_say_what_to_do() {
    let answer = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>
<BucketName>my-bucket</BucketName><RequestId>4442587FB7D0A2F9</RequestId></Error>"#;
    let (code, message) = parse_error(answer);
    assert_eq!(code, "NoSuchBucket");
    assert_eq!(
        refusal(StatusCode::NOT_FOUND, &code, &message),
        StoreError::Io("no such bucket: The specified bucket does not exist".into())
    );
    assert_eq!(parse_error(b""), (String::new(), String::new()));
    assert_eq!(
        refusal(StatusCode::NOT_FOUND, "NoSuchKey", ""),
        StoreError::NotFound
    );
    for code in [
        "AccessDenied",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
    ] {
        assert_eq!(
            refusal(StatusCode::FORBIDDEN, code, "no"),
            StoreError::Unauthorized
        );
    }
    assert_eq!(
        refusal(StatusCode::CONFLICT, "ConditionalRequestConflict", ""),
        StoreError::PreconditionFailed
    );
    assert!(matches!(
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "Reduce your request rate"
        ),
        StoreError::Unavailable(_)
    ));
    assert!(matches!(
        refusal(
            StatusCode::MOVED_PERMANENTLY,
            "PermanentRedirect",
            "use another endpoint"
        ),
        StoreError::Io(_)
    ));
}

/// The store against the service `SHELLRS_TEST_S3_ENDPOINT` names, with
/// `SHELLRS_TEST_S3_ACCESS_KEY` and `SHELLRS_TEST_S3_SECRET_KEY` (and
/// `SHELLRS_TEST_S3_REGION`, `SHELLRS_TEST_S3_PATH_STYLE`, 1 unless 0).
/// Each test goes in a bucket of this run's own, which it makes; what it
/// writes stays. Without the variables, the tests pass untried.
mod service {
    use super::*;
    use crate::testing::{Device, password};
    use crate::vault::tests::FAST;
    use crate::{RecordData, create_vault};

    struct Service {
        location: S3Location,
        access_key: String,
        secret_key: String,
    }

    fn service(test: &str) -> Option<Service> {
        let var = |name: &str| std::env::var(format!("SHELLRS_TEST_S3_{name}")).ok();
        let endpoint = var("ENDPOINT")?;
        let service = Service {
            location: S3Location {
                endpoint,
                region: var("REGION").unwrap_or_default(),
                bucket: format!("shellrs-test-{}-{test}", std::process::id()),
                prefix: "ShellRS 同步".into(),
                path_style: var("PATH_STYLE").as_deref() != Some("0"),
            },
            access_key: var("ACCESS_KEY").unwrap_or_default(),
            secret_key: var("SECRET_KEY").unwrap_or_default(),
        };
        // Its bucket, made through the store's own signing.
        let store = service.store();
        let made = store
            .send(Request {
                method: Method::PUT,
                key: None,
                query: Vec::new(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .unwrap();
        assert!(
            made.status().is_success(),
            "making the bucket: {}",
            made.status()
        );
        Some(service)
    }

    impl Service {
        fn store(&self) -> S3Store {
            self.store_as(&self.secret_key)
        }

        fn store_as(&self, secret: &str) -> S3Store {
            S3Store::new(
                &self.location,
                &self.access_key,
                secret,
                "shellrs-sync tests",
            )
            .unwrap()
        }
    }

    #[test]
    #[ignore = "needs an S3 service"]
    fn a_service_holds_files_as_every_store_does() {
        let Some(service) = service("files") else {
            return;
        };
        let store = service.store();
        assert_eq!(store.list("shellrs-sync/v1/devices".into()), Ok(Vec::new()));
        let first = store
            .put(
                "a/b/c.srs".into(),
                b"hello".to_vec(),
                PutCondition::Overwrite,
            )
            .unwrap();
        let fetched = store.get("a/b/c.srs".into(), 100).unwrap();
        assert_eq!(fetched.bytes, b"hello");
        assert_eq!(fetched.etag, first);
        let listed = store.list("a/b".into()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!((listed[0].name.as_str(), listed[0].size), ("c.srs", 5));
        assert_eq!(listed[0].etag, first);
        // A listing of a folder holds nothing of the folders in it.
        assert_eq!(store.list("a".into()), Ok(Vec::new()));
        assert_eq!(store.get("a/b/c.srs".into(), 2), Err(StoreError::TooLarge));
        assert_eq!(store.get("a/b/none".into(), 2), Err(StoreError::NotFound));
        store.delete("a/b/c.srs".into()).unwrap();
        assert_eq!(store.list("a/b".into()), Ok(Vec::new()));
        assert_eq!(
            service.store_as("wrong").list("a".into()),
            Err(StoreError::Unauthorized)
        );
    }

    /// What a service that keeps the conditions of writes keeps, natively
    /// or through a HEAD first.
    #[test]
    #[ignore = "needs an S3 service"]
    fn a_service_keeps_the_conditions_of_writes() {
        let Some(service) = service("conditions") else {
            return;
        };
        let store = service.store();
        let first = store
            .put("f".into(), b"1".to_vec(), PutCondition::Absent)
            .unwrap();
        assert_eq!(
            store.put("f".into(), b"2".to_vec(), PutCondition::Absent),
            Err(StoreError::PreconditionFailed)
        );
        let second = store
            .put(
                "f".into(),
                b"22".to_vec(),
                PutCondition::Matches(first.clone()),
            )
            .unwrap();
        assert_ne!(second, first);
        assert_eq!(
            store.put("f".into(), b"3".to_vec(), PutCondition::Matches(first)),
            Err(StoreError::PreconditionFailed)
        );
        assert_eq!(store.get("f".into(), 9).unwrap().bytes, b"22");
    }

    #[test]
    #[ignore = "needs an S3 service"]
    fn devices_sync_through_a_service() {
        let Some(service) = service("devices") else {
            return;
        };
        let store = service.store();
        let keys = create_vault(
            &store,
            "correct horse",
            FAST,
            &mut crate::FixedEnv::new(0, 3),
        )
        .unwrap();
        let mut a = Device::new('a', &keys, 1_800_000_000_000);
        let mut b = Device::new('b', &keys, 1_800_000_000_000);
        let (id, secret) = password("root", "web", "pw-web");
        a.put(&id, secret);
        a.put("g1", crate::testing::group("ops", None));
        a.sync(&store);
        b.sync(&store);
        assert_eq!(b.data(), a.data());
        assert!(
            b.data()
                .values()
                .any(|data| matches!(data, RecordData::Password(_)))
        );
        // Once a has read b's file, nothing changed: a round reads none.
        a.sync(&store);
        a.wait(1000);
        let (report, _) = a.sync(&store);
        assert_eq!(report.downloaded, 0);
    }
}
