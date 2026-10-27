//! A folder in a bucket of S3, or of a service that speaks its API: AWS,
//! Cloudflare R2, MinIO, Backblaze B2, 阿里云 OSS, 腾讯云 COS and the like.
//!
//! ListObjectsV2 lists a folder with each object's ETag, which GetObject
//! and PutObject give alike: an object's tag is its ETag, whichever way it
//! was had. Requests are signed here (Signature Version 4, in the
//! `Authorization` header).
//!
//! Services have their ways, each met here:
//! - A write's condition goes as `If-None-Match: *` or `If-Match`, which
//!   AWS takes since 2024. A service that refuses them as not implemented
//!   is written to after a HEAD instead, from then on; one that ignores
//!   them overwrites, which a round survives, as each device writes only
//!   its own file.
//! - A bucket is reached as `bucket.endpoint` or, path-style, as
//!   `endpoint/bucket` (MinIO and other self-hosted services).
//! - A clock that is wrong by more than the service allows (15 minutes on
//!   AWS) gets the request refused: it is signed again with the service's
//!   time, as its answer gives it.
//! - Every request has a time limit.

use std::fmt;
use std::io::Read as _;
use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit as _, Mac as _};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::blocking::{Client, Response};
use reqwest::header::{CONTENT_LENGTH, DATE, ETAG, HeaderMap};
use reqwest::{Method, StatusCode, Url};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::webdav::{etag_of, etag_tag, parse_http_date};
use super::{Fetched, PutCondition, RemoteFile, SyncStore};
use crate::{StoreError, hex};

const TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A listing page or an error larger than this is not one of ours.
const MAX_ANSWER: u64 = 8 << 20;

/// Where a bucket's folder is: what the settings keep, without the keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Location {
    /// The service's address, such as `https://s3.us-east-1.amazonaws.com`.
    pub endpoint: String,
    /// `us-east-1` when empty; Cloudflare R2's is `auto`.
    pub region: String,
    pub bucket: String,
    /// The folder in the bucket sync goes in; empty for its top.
    pub prefix: String,
    /// The bucket as the address's first segment rather than its host.
    pub path_style: bool,
}

pub struct S3Store {
    client: Client,
    endpoint: Url,
    region: String,
    bucket: String,
    /// The prefix, without a leading `/` and ending in one unless empty.
    prefix: String,
    path_style: bool,
    access_key: String,
    secret_key: Zeroizing<String>,
    /// How far ahead the service's clock is, in seconds, once it said.
    skew: AtomicI64,
    /// Whether the service takes conditional writes, once it refused them.
    conditions: AtomicU8,
}

const CONDITIONS_TAKEN: u8 = 0;
const CONDITIONS_REFUSED: u8 = 1;

impl fmt::Debug for S3Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Store")
            .field("endpoint", &self.endpoint.as_str())
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

/// A request before it is signed.
struct Request<'a> {
    method: Method,
    /// The object's key in the bucket; `None` for the bucket itself.
    key: Option<&'a str>,
    query: Vec<(&'static str, String)>,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl S3Store {
    /// The folder at `location`, signing in with `access_key` and
    /// `secret_key`. Requests say they come from `user_agent`.
    pub fn new(
        location: &S3Location,
        access_key: &str,
        secret_key: &str,
        user_agent: &str,
    ) -> Result<Self, StoreError> {
        let endpoint = Url::parse(location.endpoint.trim())
            .map_err(|error| StoreError::Io(format!("not an address: {error}")))?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            return Err(StoreError::Io(format!(
                "not an S3 address: {}",
                location.endpoint
            )));
        }
        let bucket = location.bucket.trim().to_owned();
        if bucket.is_empty() || bucket.contains(['/', '\\']) {
            return Err(StoreError::Io(format!("not a bucket name: {bucket}")));
        }
        let region = match location.region.trim() {
            "" => "us-east-1".to_owned(),
            region => region.to_owned(),
        };
        let prefix = location.prefix.trim().trim_matches('/');
        let prefix = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        let client = Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(user_agent)
            .build()
            .map_err(|error| StoreError::Io(error.to_string()))?;
        Ok(Self {
            client,
            endpoint,
            region,
            bucket,
            prefix,
            path_style: location.path_style,
            access_key: access_key.trim().to_owned(),
            secret_key: Zeroizing::new(secret_key.to_owned()),
            skew: AtomicI64::new(0),
            conditions: AtomicU8::new(CONDITIONS_TAKEN),
        })
    }

    /// The key of `path` in the bucket.
    fn key(&self, path: &str) -> Result<String, StoreError> {
        for part in path.split('/') {
            if part == "." || part == ".." || part.contains(['\\', '\0']) {
                return Err(StoreError::Io(format!("not a path in the store: {path}")));
            }
        }
        Ok(format!("{}{}", self.prefix, path.trim_matches('/')))
    }

    /// The host requests go to and the path of `key` there, encoded.
    fn host_and_path(&self, key: Option<&str>) -> (String, String) {
        let host = self.endpoint.host_str().unwrap_or_default();
        let port = self
            .endpoint
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        let base = self.endpoint.path().trim_end_matches('/');
        let key = key.map(|key| format!("/{}", uri_encode(key, false)));
        if self.path_style {
            let path = format!(
                "{base}/{}{}",
                uri_encode(&self.bucket, true),
                key.unwrap_or_default()
            );
            (format!("{host}{port}"), path)
        } else {
            let path = format!("{base}{}", key.unwrap_or_else(|| "/".into()));
            (format!("{}.{host}{port}", self.bucket), path)
        }
    }

    /// Sign `request` and send it; once more with the service's time when
    /// it refused this computer's.
    fn send(&self, request: Request<'_>) -> Result<Response, StoreError> {
        for _ in 0..2 {
            let response = self.send_signed(&request)?;
            if response.status() != StatusCode::FORBIDDEN {
                return Ok(response);
            }
            let headers = response.headers().clone();
            let answer = read_limited(response, MAX_ANSWER)?;
            let (code, message) = parse_error(&answer);
            if code != "RequestTimeTooSkewed" {
                return Err(refusal(StatusCode::FORBIDDEN, &code, &message));
            }
            let Some(theirs) =
                header_text(&headers, DATE.as_str()).and_then(|date| parse_http_date(&date))
            else {
                return Err(refusal(StatusCode::FORBIDDEN, &code, &message));
            };
            self.skew
                .store(theirs as i64 - now_secs() as i64, Ordering::Relaxed);
        }
        Err(StoreError::Io("this computer's clock is wrong".into()))
    }

    fn send_signed(&self, request: &Request<'_>) -> Result<Response, StoreError> {
        let (host, path) = self.host_and_path(request.key);
        let mut query: Vec<(String, String)> = request
            .query
            .iter()
            .map(|(name, value)| (uri_encode(name, true), uri_encode(value, true)))
            .collect();
        query.sort();
        let query = query
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        let now = now_secs().saturating_add_signed(self.skew.load(Ordering::Relaxed));
        let amz_date = amz_date(now);
        let payload = hex::encode(&Sha256::digest(&request.body));
        let canonical = canonical_request(
            request.method.as_str(),
            &path,
            &query,
            &[
                ("host", &host),
                ("x-amz-content-sha256", &payload),
                ("x-amz-date", &amz_date),
            ],
            &payload,
        );
        let scope = format!("{}/{}/s3/aws4_request", &amz_date[..8], self.region);
        let signature = signature(&self.secret_key, &amz_date, &self.region, &canonical);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}",
            self.access_key
        );
        let mut url = format!("{}://{host}{path}", self.endpoint.scheme());
        if !query.is_empty() {
            url = format!("{url}?{query}");
        }
        let url = Url::parse(&url).map_err(|error| StoreError::Io(error.to_string()))?;
        let mut builder = self
            .client
            .request(request.method.clone(), url)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload)
            .header("authorization", authorization);
        for (name, value) in &request.headers {
            builder = builder.header(*name, value);
        }
        if !request.body.is_empty() || request.method == Method::PUT {
            builder = builder.body(request.body.clone());
        }
        builder.send().map_err(|error| {
            if error.is_timeout() {
                StoreError::Timeout
            } else {
                StoreError::Unavailable(error.to_string())
            }
        })
    }

    /// A refusal, read from the service's answer.
    fn refused(&self, response: Response) -> StoreError {
        let status = response.status();
        let answer = read_limited(response, MAX_ANSWER).unwrap_or_default();
        let (code, message) = parse_error(&answer);
        refusal(status, &code, &message)
    }

    /// The tag `key` has now, `None` when there is no such object.
    fn tag_of(&self, key: &str) -> Result<Option<String>, StoreError> {
        let response = self.send(Request {
            method: Method::HEAD,
            key: Some(key),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        })?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => Ok(Some(
                header_text(response.headers(), ETAG.as_str())
                    .map(|etag| etag_tag(&etag))
                    .unwrap_or_default(),
            )),
            status => Err(refusal(status, "", "")),
        }
    }

    fn put_object(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Option<(&'static str, String)>,
    ) -> Result<Response, StoreError> {
        self.send(Request {
            method: Method::PUT,
            key: Some(key),
            query: Vec::new(),
            headers: condition.into_iter().collect(),
            body: bytes.to_vec(),
        })
    }

    /// Write after looking, for a service that takes no conditions.
    fn put_checked(
        &self,
        key: &str,
        bytes: &[u8],
        cond: &PutCondition,
    ) -> Result<Response, StoreError> {
        let now = self.tag_of(key)?;
        let holds = match cond {
            PutCondition::Overwrite => true,
            PutCondition::Absent => now.is_none(),
            PutCondition::Matches(expected) => now.as_deref() == Some(expected.as_str()),
        };
        if !holds {
            return Err(StoreError::PreconditionFailed);
        }
        self.put_object(key, bytes, None)
    }
}

impl SyncStore for S3Store {
    fn list(&self, dir: String) -> Result<Vec<RemoteFile>, StoreError> {
        let prefix = format!("{}/", self.key(&dir)?.trim_end_matches('/'));
        let prefix = prefix.trim_start_matches('/').to_owned();
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type", "2".to_owned()),
                ("prefix", prefix.clone()),
                ("delimiter", "/".to_owned()),
            ];
            if let Some(token) = token.take() {
                query.push(("continuation-token", token));
            }
            let response = self.send(Request {
                method: Method::GET,
                key: None,
                query,
                headers: Vec::new(),
                body: Vec::new(),
            })?;
            if !response.status().is_success() {
                return Err(self.refused(response));
            }
            let page = parse_listing(&read_limited(response, MAX_ANSWER)?)?;
            out.extend(page.objects.into_iter().filter_map(|object| {
                let name = object.key.strip_prefix(&prefix)?;
                (!name.is_empty() && !name.contains('/')).then(|| RemoteFile {
                    name: name.to_owned(),
                    etag: etag_tag(&object.etag),
                    size: object.size,
                })
            }));
            match page.next {
                Some(next) if page.truncated => token = Some(next),
                _ => break,
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn get(&self, path: String, max_bytes: u64) -> Result<Fetched, StoreError> {
        let key = self.key(&path)?;
        let response = self.send(Request {
            method: Method::GET,
            key: Some(&key),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        })?;
        if !response.status().is_success() {
            return Err(self.refused(response));
        }
        let headers = response.headers().clone();
        if header_text(&headers, CONTENT_LENGTH.as_str())
            .and_then(|length| length.parse::<u64>().ok())
            .is_some_and(|length| length > max_bytes)
        {
            return Err(StoreError::TooLarge);
        }
        let bytes = read_limited(response, max_bytes)?;
        let etag = header_text(&headers, ETAG.as_str())
            .map(|etag| etag_tag(&etag))
            .unwrap_or_default();
        Ok(Fetched { bytes, etag })
    }

    fn put(&self, path: String, bytes: Vec<u8>, cond: PutCondition) -> Result<String, StoreError> {
        let key = self.key(&path)?;
        let condition = match &cond {
            PutCondition::Overwrite => None,
            PutCondition::Absent => Some(("if-none-match", "*".to_owned())),
            PutCondition::Matches(tag) => match etag_of(tag) {
                Some(etag) => Some(("if-match", etag)),
                // Not a tag of this service's: no object has it.
                None => return Err(StoreError::PreconditionFailed),
            },
        };
        let refused_before = self.conditions.load(Ordering::Relaxed) == CONDITIONS_REFUSED;
        let mut response = if condition.is_some() && refused_before {
            self.put_checked(&key, &bytes, &cond)?
        } else {
            self.put_object(&key, &bytes, condition.clone())?
        };
        if condition.is_some() && !refused_before {
            let status = response.status();
            if status == StatusCode::NOT_IMPLEMENTED {
                self.conditions.store(CONDITIONS_REFUSED, Ordering::Relaxed);
                response = self.put_checked(&key, &bytes, &cond)?;
            } else if status == StatusCode::BAD_REQUEST {
                let answer = read_limited(response, MAX_ANSWER)?;
                let (code, message) = parse_error(&answer);
                if code != "NotImplemented" {
                    return Err(refusal(status, &code, &message));
                }
                self.conditions.store(CONDITIONS_REFUSED, Ordering::Relaxed);
                response = self.put_checked(&key, &bytes, &cond)?;
            }
        }
        let status = response.status();
        // 409: a conditional write that lost to another at the same time.
        if status == StatusCode::PRECONDITION_FAILED || status == StatusCode::CONFLICT {
            return Err(StoreError::PreconditionFailed);
        }
        if !status.is_success() {
            return Err(self.refused(response));
        }
        match header_text(response.headers(), ETAG.as_str()) {
            Some(etag) => Ok(etag_tag(&etag)),
            None => self
                .tag_of(&key)?
                .ok_or_else(|| StoreError::Io("the object is not there after writing it".into())),
        }
    }

    /// Deleting what is not there is no error to S3, nor here.
    fn delete(&self, path: String) -> Result<(), StoreError> {
        let key = self.key(&path)?;
        let response = self.send(Request {
            method: Method::DELETE,
            key: Some(&key),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        })?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(self.refused(response))
        }
    }
}

/// A refusal, the same for every backend: by the service's error code
/// first, its status otherwise; its message where the user must act.
fn refusal(status: StatusCode, code: &str, message: &str) -> StoreError {
    let said = |what: &str| {
        if message.is_empty() {
            format!("{what} (HTTP {status})")
        } else {
            format!("{what}: {message}")
        }
    };
    match code {
        "NoSuchKey" => return StoreError::NotFound,
        "NoSuchBucket" => return StoreError::Io(said("no such bucket")),
        "AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch" | "AccountProblem" => {
            return StoreError::Unauthorized;
        }
        "PreconditionFailed" | "ConditionalRequestConflict" => {
            return StoreError::PreconditionFailed;
        }
        "SlowDown" | "ServiceUnavailable" | "InternalError" => {
            return StoreError::Unavailable(said(code));
        }
        "PermanentRedirect" | "AuthorizationHeaderMalformed" => {
            return StoreError::Io(said("another address or region"));
        }
        _ => {}
    }
    match status.as_u16() {
        401 | 403 => StoreError::Unauthorized,
        404 => StoreError::NotFound,
        412 => StoreError::PreconditionFailed,
        408 | 504 => StoreError::Timeout,
        429 | 500..=599 => StoreError::Unavailable(said("unavailable")),
        _ if code.is_empty() => StoreError::Io(format!("HTTP {status}")),
        _ => StoreError::Io(said(code)),
    }
}

fn read_limited(response: Response, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    response
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| StoreError::Unavailable(error.to_string()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(StoreError::TooLarge);
    }
    Ok(bytes)
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Percent-encoding as Signature Version 4 wants it: everything but
/// letters, digits and `-._~`, and `/` too unless it separates a path.
fn uri_encode(text: &str, slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b'/' if !slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The canonical request of Signature Version 4: `headers` lower-case and
/// in order, their values as sent.
fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload: &str,
) -> String {
    let mut canonical = format!("{method}\n{path}\n{query}\n");
    for (name, value) in headers {
        canonical.push_str(&format!("{name}:{}\n", value.trim()));
    }
    let signed = headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    canonical.push_str(&format!("\n{signed}\n{payload}"));
    canonical
}

/// The signature of `canonical` (a canonical request), made at `amz_date`
/// (`20130524T000000Z`) in `region`.
fn signature(secret: &str, amz_date: &str, region: &str, canonical: &str) -> String {
    let hmac = |key: &[u8], data: &str| -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("a key of any length");
        mac.update(data.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    let day = &amz_date[..8];
    let scope = format!("{day}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(&Sha256::digest(canonical.as_bytes()))
    );
    let key = hmac(format!("AWS4{secret}").as_bytes(), day);
    let key = hmac(&key, region);
    let key = hmac(&key, "s3");
    let key = hmac(&key, "aws4_request");
    hex::encode(&hmac(&key, &to_sign))
}

/// `20130524T000000Z` for a time in seconds since the epoch.
fn amz_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // The civil date of a day count, after Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// An object of a listing.
#[derive(Debug, Default, PartialEq, Eq)]
struct Object {
    key: String,
    etag: String,
    size: u64,
}

/// A page of a ListObjectsV2 answer.
#[derive(Debug, Default, PartialEq, Eq)]
struct Listing {
    objects: Vec<Object>,
    truncated: bool,
    next: Option<String>,
}

/// The text of each element of `xml`, by its name without namespace, with
/// the name of the element it is in: enough for S3's flat answers.
fn elements(xml: &[u8]) -> Result<Vec<(String, String, String)>, StoreError> {
    let bad = |error: &dyn fmt::Display| StoreError::Io(format!("an unreadable answer: {error}"));
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut out = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|error| bad(&error))?
        {
            Event::Start(start) => {
                path.push(String::from_utf8_lossy(start.local_name().as_ref()).into_owned());
                text.clear();
            }
            Event::Text(chunk) => text.push_str(&chunk.decode().map_err(|error| bad(&error))?),
            Event::CData(chunk) => text.push_str(&chunk.decode().map_err(|error| bad(&error))?),
            Event::GeneralRef(reference) => {
                let name = reference.decode().map_err(|error| bad(&error))?;
                let raw = format!("&{name};");
                match quick_xml::escape::unescape(&raw) {
                    Ok(resolved) => text.push_str(&resolved),
                    Err(_) => text.push_str(&raw),
                }
            }
            Event::End(_) => {
                let Some(name) = path.pop() else {
                    continue;
                };
                let parent = path.last().cloned().unwrap_or_default();
                out.push((parent, name, std::mem::take(&mut text).trim().to_owned()));
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn parse_listing(xml: &[u8]) -> Result<Listing, StoreError> {
    let mut listing = Listing::default();
    let mut object = Object::default();
    for (parent, name, text) in elements(xml)? {
        match (parent.as_str(), name.as_str()) {
            ("Contents", "Key") => object.key = text,
            ("Contents", "ETag") => object.etag = text,
            ("Contents", "Size") => object.size = text.parse().unwrap_or(0),
            (_, "Contents") => listing.objects.push(std::mem::take(&mut object)),
            ("ListBucketResult", "IsTruncated") => listing.truncated = text == "true",
            ("ListBucketResult", "NextContinuationToken") if !text.is_empty() => {
                listing.next = Some(text);
            }
            _ => {}
        }
    }
    Ok(listing)
}

/// An error answer's code and message, empty when it has none.
fn parse_error(xml: &[u8]) -> (String, String) {
    let mut code = String::new();
    let mut message = String::new();
    for (parent, name, text) in elements(xml).unwrap_or_default() {
        match (parent.as_str(), name.as_str()) {
            ("Error", "Code") => code = text,
            ("Error", "Message") => message = text,
            _ => {}
        }
    }
    (code, message)
}

#[cfg(test)]
#[path = "s3_tests.rs"]
mod tests;
