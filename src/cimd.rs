//! Bounded, unadvertised OAuth Client ID Metadata Document discovery.
//! The policy resolver must still authorize scopes, resources, and browser origins.
use reqwest::{StatusCode, header};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use url::{Host, Url};

const MAX_DOCUMENT_BYTES: usize = 5 * 1024;
const MAX_CACHE_ENTRIES: usize = 128;
const MAX_CLIENT_ID_BYTES: usize = 2048;
const MAX_REDIRECTS: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CACHE_TTL: Duration = Duration::from_secs(300);
type BoxFuture<T> = Pin<Box<dyn Future<Output = Result<T, CimdError>> + Send>>;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CimdError {
    #[error("invalid client metadata URL")]
    InvalidUrl,
    #[error("unsafe client metadata destination")]
    UnsafeDestination,
    #[error("client metadata request failed")]
    FetchFailed,
    #[error("invalid client metadata document")]
    InvalidDocument,
    #[error("client metadata service is busy")]
    Busy,
}

/// Only validated identity and redirect declarations cross this boundary.
/// Accessors return borrowed data; no mutable metadata or URL-bearing extras survive.
#[derive(Debug, Clone)]
pub struct ClientMetadataDocument {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    refresh_allowed: bool,
}
impl ClientMetadataDocument {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn client_name(&self) -> &str {
        &self.client_name
    }
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }
    pub fn refresh_allowed(&self) -> bool {
        self.refresh_allowed
    }
}

struct ResponseDocument {
    status: StatusCode,
    content_type: Option<String>,
    cache_control: Option<Vec<String>>,
    age: u64,
    body: Vec<u8>,
}
trait Resolver: Send + Sync {
    fn resolve(&self, host: String, port: u16) -> BoxFuture<Vec<SocketAddr>>;
}
trait Transport: Send + Sync {
    fn fetch(&self, url: Url, host: String, addrs: Vec<SocketAddr>) -> BoxFuture<ResponseDocument>;
}
struct SystemResolver;
impl Resolver for SystemResolver {
    fn resolve(&self, host: String, port: u16) -> BoxFuture<Vec<SocketAddr>> {
        Box::pin(async move {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|iter| iter.collect())
                .map_err(|_| CimdError::FetchFailed)
        })
    }
}
struct PinnedTransport {
    #[cfg(test)]
    test_root: Option<reqwest::Certificate>,
}
impl Transport for PinnedTransport {
    fn fetch(&self, url: Url, host: String, addrs: Vec<SocketAddr>) -> BoxFuture<ResponseDocument> {
        #[cfg(test)]
        let test_root = self.test_root.clone();
        Box::pin(async move {
            // resolve_to_addrs replaces DNS for this host while the original URL
            // remains the request target, preserving HTTP Host and TLS SNI.
            let builder = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .http1_only()
                .pool_max_idle_per_host(0)
                .resolve_to_addrs(&host, &addrs);
            #[cfg(test)]
            let builder = if let Some(root) = test_root {
                builder.add_root_certificate(root)
            } else {
                builder
            };
            let client = builder.build().map_err(|_| CimdError::FetchFailed)?;
            let mut response = client
                .get(url)
                .send()
                .await
                .map_err(|_| CimdError::FetchFailed)?;
            if !response
                .remote_addr()
                .is_some_and(|peer| addrs.contains(&peer))
            {
                return Err(CimdError::UnsafeDestination);
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_DOCUMENT_BYTES as u64)
            {
                return Err(CimdError::InvalidDocument);
            }
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            // Collect every field: a later no-store must override an earlier max-age.
            // Invalid header text or Age makes the response ineligible for caching.
            let cache_control = response
                .headers()
                .get_all(header::CACHE_CONTROL)
                .iter()
                .map(|v| v.to_str().ok().map(str::to_owned))
                .collect::<Option<Vec<_>>>();
            let age = response
                .headers()
                .get_all(header::AGE)
                .iter()
                .try_fold(0u64, |max, value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(|age| max.max(age))
                        .ok_or(())
                })
                .unwrap_or(u64::MAX);
            let status = response.status();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| CimdError::FetchFailed)? {
                if body.len().saturating_add(chunk.len()) > MAX_DOCUMENT_BYTES {
                    return Err(CimdError::InvalidDocument);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(ResponseDocument {
                status,
                content_type,
                cache_control,
                age,
                body,
            })
        })
    }
}

/// Shared bounded fetcher. It never caches failed requests or invalid documents.
pub struct CimdFetcher {
    resolver: Arc<dyn Resolver>,
    transport: Arc<dyn Transport>,
    concurrency: Semaphore,
    cache: Mutex<HashMap<String, (Instant, Arc<ClientMetadataDocument>)>>,
}
impl Default for CimdFetcher {
    fn default() -> Self {
        Self::new()
    }
}
impl CimdFetcher {
    pub fn new() -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
            transport: Arc::new(PinnedTransport {
                #[cfg(test)]
                test_root: None,
            }),
            concurrency: Semaphore::new(8),
            cache: Mutex::new(HashMap::new()),
        }
    }
    pub async fn fetch(&self, client_id: &str) -> Result<Arc<ClientMetadataDocument>, CimdError> {
        let (url, host, port) = validate_client_id(client_id)?;
        {
            let cache = self.cache.lock().await;
            if let Some((expiry, document)) = cache.get(client_id)
                && *expiry > Instant::now()
            {
                return Ok(Arc::clone(document));
            }
        }
        let _permit = self
            .concurrency
            .try_acquire()
            .map_err(|_| CimdError::Busy)?;
        let (document, ttl) = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let addrs = self.resolver.resolve(host.clone(), port).await?;
            if addrs.is_empty()
                || addrs.len() > 32
                || addrs
                    .iter()
                    .any(|addr| addr.port() != port || !public_ip(addr.ip()))
            {
                return Err(CimdError::UnsafeDestination);
            }
            let response = self.transport.fetch(url, host, addrs).await?;
            if response.status != StatusCode::OK {
                return Err(CimdError::FetchFailed);
            }
            let content_type = response
                .content_type
                .as_deref()
                .ok_or(CimdError::InvalidDocument)?;
            let mime = content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if mime != "application/json"
                && !(mime.starts_with("application/") && mime.ends_with("+json"))
            {
                return Err(CimdError::InvalidDocument);
            }
            if response.body.len() > MAX_DOCUMENT_BYTES {
                return Err(CimdError::InvalidDocument);
            }
            let document = validate_document(client_id, &response.body)?;
            Ok((
                document,
                cache_ttl(response.cache_control.as_deref(), response.age),
            ))
        })
        .await
        .map_err(|_| CimdError::FetchFailed)??;
        let document = Arc::new(document);
        if let Some(ttl) = ttl {
            let mut cache = self.cache.lock().await;
            cache.retain(|_, (expiry, _)| *expiry > Instant::now());
            if cache.len() >= MAX_CACHE_ENTRIES
                && let Some(key) = cache.keys().next().cloned()
            {
                cache.remove(&key);
            }
            cache.insert(
                client_id.to_owned(),
                (Instant::now() + ttl, Arc::clone(&document)),
            );
        }
        Ok(document)
    }
    #[cfg(test)]
    fn with_test_io(resolver: Arc<dyn Resolver>, transport: Arc<dyn Transport>) -> Self {
        Self {
            resolver,
            transport,
            concurrency: Semaphore::new(8),
            cache: Mutex::new(HashMap::new()),
        }
    }
}

fn validate_client_id(raw: &str) -> Result<(Url, String, u16), CimdError> {
    if raw.is_empty()
        || raw.len() > MAX_CLIENT_ID_BYTES
        || !raw.starts_with("https://")
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(CimdError::InvalidUrl);
    }
    // Draft-00 requires an actual path and forbids dot segments. Eri additionally
    // rejects query strings and URL-parser normalization as local policy.
    let after_scheme = &raw["https://".len()..];
    let path_start = after_scheme.find('/').ok_or(CimdError::InvalidUrl)?;
    let path = after_scheme[path_start..]
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    if path.split('/').any(|segment| matches!(segment, "." | "..")) {
        return Err(CimdError::InvalidUrl);
    }
    let url = Url::parse(raw).map_err(|_| CimdError::InvalidUrl)?;
    if url.as_str() != raw
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(CimdError::InvalidUrl);
    }
    let Host::Domain(host) = url.host().ok_or(CimdError::InvalidUrl)? else {
        return Err(CimdError::UnsafeDestination);
    };
    if !public_dns_name(host) {
        return Err(CimdError::UnsafeDestination);
    }
    let port = url.port_or_known_default().ok_or(CimdError::InvalidUrl)?;
    Ok((url.clone(), host.to_owned(), port))
}
fn public_dns_name(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || !host.contains('.') || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    let last = host.rsplit('.').next().unwrap_or("");
    if matches!(
        last,
        "localhost"
            | "local"
            | "internal"
            | "test"
            | "invalid"
            | "example"
            | "onion"
            | "arpa"
            | "home"
            | "lan"
    ) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => public_v4(v),
        IpAddr::V6(v) => {
            if v.to_ipv4_mapped().is_some() {
                return false;
            }
            let s = v.segments();
            // Conservative global-unicast allowlist with known special-purpose ranges denied.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x01ff || s[1] == 0x0db8))
                && s[0] != 0x2002
                && s[0] != 0x3fff
                && !(s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000)
        }
    }
}
fn public_v4(v: Ipv4Addr) -> bool {
    let [a, b, c, _] = v.octets();
    match a {
        0 | 10 | 127 | 224..=255 => false,
        100 => !(64..=127).contains(&b),
        169 => b != 254,
        172 => !(16..=31).contains(&b),
        192 => {
            b != 0
                && b != 168
                && !matches!(
                    (b, c),
                    (2, _) | (31, 196) | (52, 193) | (88, 99) | (175, 48)
                )
        }
        198 => b != 18 && b != 19 && (b != 51 || c != 100),
        203 => b != 0 || c != 113,
        _ => true,
    }
}

struct StrictObject(serde_json::Map<String, serde_json::Value>);
impl<'de> Deserialize<'de> for StrictObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = StrictObject;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON object without duplicate fields")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut object = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if object.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate field"));
                    }
                }
                Ok(StrictObject(object))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
fn validate_document(client_id: &str, body: &[u8]) -> Result<ClientMetadataDocument, CimdError> {
    // Unknown extensions are inert; duplicate top-level fields cannot override policy.
    let value: StrictObject =
        serde_json::from_slice(body).map_err(|_| CimdError::InvalidDocument)?;
    let obj = &value.0;
    let get = |key: &str| obj.get(key).ok_or(CimdError::InvalidDocument);
    let id = get("client_id")?
        .as_str()
        .ok_or(CimdError::InvalidDocument)?;
    let name = get("client_name")?
        .as_str()
        .ok_or(CimdError::InvalidDocument)?;
    if id.as_bytes() != client_id.as_bytes() || !safe_name(name) {
        return Err(CimdError::InvalidDocument);
    }
    if obj.get("client_secret").is_some()
        || obj.get("client_secret_expires_at").is_some()
        || obj.get("jwks").is_some()
        || obj.get("jwks_uri").is_some()
    {
        return Err(CimdError::InvalidDocument);
    }
    if obj
        .get("token_endpoint_auth_method")
        .and_then(|v| v.as_str())
        != Some("none")
    {
        return Err(CimdError::InvalidDocument);
    }
    let grant_types = obj
        .get("grant_types")
        .map(|v| v.as_array().ok_or(CimdError::InvalidDocument))
        .transpose()?;
    let refresh_allowed = if let Some(grants) = grant_types {
        if grants.is_empty()
            || grants.len() > 2
            || (grants.len() == 2 && grants[0] == grants[1])
            || grants
                .iter()
                .any(|v| !matches!(v.as_str(), Some("authorization_code" | "refresh_token")))
            || !grants
                .iter()
                .any(|v| v.as_str() == Some("authorization_code"))
        {
            return Err(CimdError::InvalidDocument);
        }
        grants.iter().any(|v| v.as_str() == Some("refresh_token"))
    } else {
        false
    };
    if obj.get("response_types").is_some_and(|v| {
        v.as_array()
            .is_none_or(|a| a.len() != 1 || a[0].as_str() != Some("code"))
    }) {
        return Err(CimdError::InvalidDocument);
    }
    let redirects = get("redirect_uris")?
        .as_array()
        .ok_or(CimdError::InvalidDocument)?;
    if redirects.is_empty() || redirects.len() > MAX_REDIRECTS {
        return Err(CimdError::InvalidDocument);
    }
    let mut redirect_uris = Vec::with_capacity(redirects.len());
    for item in redirects {
        let raw = item.as_str().ok_or(CimdError::InvalidDocument)?;
        if !safe_redirect(raw) || redirect_uris.iter().any(|r| r == raw) {
            return Err(CimdError::InvalidDocument);
        }
        redirect_uris.push(raw.to_owned());
    }
    Ok(ClientMetadataDocument {
        client_id: id.to_owned(),
        client_name: name.to_owned(),
        redirect_uris,
        refresh_allowed,
    })
}
fn safe_name(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && n == name && n.chars().count() <= 128 && !n.chars().any(|c| c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '<' | '>' | '&'))
}
fn safe_redirect(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 2048 {
        return false;
    }
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if url.as_str() != raw
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match (url.scheme(), url.host()) {
        ("https", Some(Host::Domain(host))) => public_dns_name(host),
        ("http", Some(Host::Ipv4(ip))) => ip == Ipv4Addr::LOCALHOST && url.port().is_some(),
        ("http", Some(Host::Ipv6(ip))) => ip == Ipv6Addr::LOCALHOST && url.port().is_some(),
        _ => false,
    }
}
fn cache_ttl(headers: Option<&[String]>, response_age: u64) -> Option<Duration> {
    let headers = headers?;
    let mut maximum_age = None::<u64>;
    for directive in headers
        .iter()
        .flat_map(|field| field.split(','))
        .map(str::trim)
    {
        if directive.is_empty() || directive.contains(';') {
            return None;
        }
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return None;
        }
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "no-store" | "no-cache" | "private"
        ) {
            return None;
        }
        let value = value.map(|value| {
            if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                &value[1..value.len() - 1]
            } else {
                value
            }
        });
        if let Some(value) = value
            && (value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_graphic())
                || value.contains('"'))
        {
            return None;
        }
        if name.eq_ignore_ascii_case("max-age") {
            let seconds = value?.parse::<u64>().ok()?;
            maximum_age = Some(maximum_age.map_or(seconds, |current| current.min(seconds)));
        }
    }
    // No explicit freshness means no cache; this also respects an earlier
    // Expires date without depending on the remote server clock.
    let ttl = Duration::from_secs(maximum_age?).min(MAX_CACHE_TTL);
    ttl.checked_sub(Duration::from_secs(response_age))
        .filter(|ttl| !ttl.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const ID: &str = "https://client.example.org/metadata.json";
    struct FakeResolver(Vec<SocketAddr>);
    impl Resolver for FakeResolver {
        fn resolve(&self, _: String, _: u16) -> BoxFuture<Vec<SocketAddr>> {
            let v = self.0.clone();
            Box::pin(async move { Ok(v) })
        }
    }
    struct FakeTransport {
        calls: AtomicUsize,
        body: Vec<u8>,
        status: StatusCode,
        cache: Vec<String>,
    }
    impl Transport for FakeTransport {
        fn fetch(&self, _: Url, _: String, _: Vec<SocketAddr>) -> BoxFuture<ResponseDocument> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let body = self.body.clone();
            let status = self.status;
            let cache_control = Some(self.cache.clone());
            Box::pin(async move {
                Ok(ResponseDocument {
                    status,
                    content_type: Some("application/json".into()),
                    cache_control,
                    age: 0,
                    body,
                })
            })
        }
    }
    fn fixture() -> Vec<u8> {
        format!(r#"{{"client_id":"{ID}","client_name":"Example Client","redirect_uris":["https://client.example.org/callback","http://127.0.0.1:3456/callback"],"token_endpoint_auth_method":"none"}}"#).into_bytes()
    }
    fn fetcher(
        ips: Vec<SocketAddr>,
        body: Vec<u8>,
        status: StatusCode,
        cache: Option<&str>,
    ) -> (CimdFetcher, Arc<FakeTransport>) {
        let transport = Arc::new(FakeTransport {
            calls: AtomicUsize::new(0),
            body,
            status,
            cache: cache.into_iter().map(str::to_owned).collect(),
        });
        (
            CimdFetcher::with_test_io(Arc::new(FakeResolver(ips)), transport.clone()),
            transport,
        )
    }
    fn public_addr() -> SocketAddr {
        "8.8.8.8:443".parse().unwrap()
    }
    #[test]
    fn url_rejects_unsafe_forms() {
        for id in [
            "http://client.example.org/doc",
            "https://user@client.example.org/doc",
            "https://client.example.org/doc#x",
            "https://client.example.org/doc?q=1",
            "https://127.0.0.1/doc",
            "https://[::ffff:127.0.0.1]/doc",
            "https://localhost/doc",
            "https://client.local/doc",
            "https://client.example.org:443/doc",
            "https://CLIENT.example.org/doc",
            "https://client.example.org",
            "https://client.example.org/a/../doc",
            "https://client.example.org/a/%2e%2e/doc",
        ] {
            assert!(validate_client_id(id).is_err(), "{id}");
        }
        assert!(validate_client_id(ID).is_ok());
        assert!(validate_client_id("https://client.example.org/").is_ok());
    }
    #[test]
    fn denies_special_address_results() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.1.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:8.8.8.8",
            "2001:db8::1",
            "2002:c0a8:101::1",
            "2620:4f:8000::1",
            "3fff::1",
            "192.31.196.1",
            "192.52.193.1",
            "192.175.48.1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
    #[tokio::test]
    async fn validates_and_caches_only_success() {
        let (cached_fetcher, transport) = fetcher(
            vec![public_addr()],
            fixture(),
            StatusCode::OK,
            Some("max-age=60"),
        );
        let doc = cached_fetcher.fetch(ID).await.unwrap();
        assert_eq!(doc.client_id(), ID);
        assert_eq!(doc.redirect_uris().len(), 2);
        assert!(!doc.refresh_allowed());
        cached_fetcher.fetch(ID).await.unwrap();
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        let (no_store_fetcher, transport) = fetcher(
            vec![public_addr()],
            fixture(),
            StatusCode::OK,
            Some("no-store"),
        );
        no_store_fetcher.fetch(ID).await.unwrap();
        no_store_fetcher.fetch(ID).await.unwrap();
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
        let (error_fetcher, transport) =
            fetcher(vec![public_addr()], fixture(), StatusCode::NOT_FOUND, None);
        assert!(error_fetcher.fetch(ID).await.is_err());
        assert!(error_fetcher.fetch(ID).await.is_err());
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn blocks_mixed_dns_before_transport() {
        let (fetcher, transport) = fetcher(
            vec![public_addr(), "127.0.0.1:443".parse().unwrap()],
            fixture(),
            StatusCode::OK,
            None,
        );
        assert!(matches!(
            fetcher.fetch(ID).await,
            Err(CimdError::UnsafeDestination)
        ));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn rejects_untrusted_metadata_fields() {
        for body in [
            String::from_utf8(fixture()).unwrap().replace(ID, "https://evil.example.org/metadata.json").into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Bad\u202eName","redirect_uris":["https://client.example.org/callback"]}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["http://localhost:8080/callback"]}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback#fragment"]}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback"],"token_endpoint_auth_method":"client_secret_basic"}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback"],"client_secret":"x"}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback"]}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback"],"token_endpoint_auth_method":"none","grant_types":["refresh_token"]}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","authorization_code"]}}"#).into_bytes(),
            format!(r#"{{"client_id":"{ID}","client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback"]}}"#).into_bytes(),
        ] { assert!(validate_document(ID, &body).is_err()); }
    }
    #[test]
    fn explicit_refresh_capability_is_retained_without_granting_scopes() {
        let body = format!(
            r#"{{"client_id":"{ID}","client_name":"Client","redirect_uris":["https://client.example.org/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"scope":"admin"}}"#
        );
        let document = validate_document(ID, body.as_bytes()).unwrap();
        assert!(document.refresh_allowed());
        assert_eq!(
            document.redirect_uris(),
            &["https://client.example.org/callback".to_owned()]
        );
    }
    #[tokio::test]
    async fn invalid_and_oversized_documents_are_never_cached() {
        for body in [b"not json".to_vec(), vec![b'x'; MAX_DOCUMENT_BYTES + 1]] {
            let (fetcher, transport) = fetcher(vec![public_addr()], body, StatusCode::OK, None);
            assert!(fetcher.fetch(ID).await.is_err());
            assert!(fetcher.fetch(ID).await.is_err());
            assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
        }
    }
    #[test]
    fn cache_freshness_respects_age_and_no_store() {
        let fields = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            cache_ttl(Some(&fields(&["Max-Age=120"])), 30),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            cache_ttl(Some(&fields(&["max-age=300", "No-Store"])), 0),
            None
        );
        assert_eq!(
            cache_ttl(Some(&fields(&["max-age=300", "MAX-AGE=0"])), 0),
            None
        );
        assert_eq!(cache_ttl(Some(&fields(&["MAX-AGE=bad"])), 0), None);
        assert_eq!(cache_ttl(Some(&fields(&["max-age=\"300"])), 0), None);
        assert_eq!(
            cache_ttl(Some(&fields(&["max-age=\"300\""])), 0),
            Some(MAX_CACHE_TTL)
        );
        assert_eq!(cache_ttl(Some(&fields(&["max-age=30"])), 30), None);
        assert_eq!(
            cache_ttl(Some(&fields(&["max-age=99999"])), 0),
            Some(MAX_CACHE_TTL)
        );
        assert_eq!(cache_ttl(None, 0), None);
        assert_eq!(cache_ttl(Some(&fields(&[])), 0), None);
        assert_eq!(cache_ttl(Some(&fields(&["max-age=300"])), u64::MAX), None);
    }
    #[tokio::test]
    async fn pinned_tls_transport_preserves_host_sni_and_all_cache_fields() {
        let cert = rustls::pki_types::CertificateDer::from(
            include_bytes!("../tests/fixtures/cimd/leaf.der").to_vec(),
        );
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("../tests/fixtures/cimd/leaf.pk8").to_vec(),
        );
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            let sni = tls.get_ref().1.server_name().unwrap().to_owned();
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let count = tls.read(&mut buf).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buf[..count]);
                assert!(request.len() < 4096);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            let body = fixture();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=300\r\nCache-Control: No-Store\r\nAge: 12\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(headers.as_bytes()).await.unwrap();
            tls.write_all(&body).await.unwrap();
            tls.flush().await.unwrap();
            (sni, request)
        });
        let root = reqwest::Certificate::from_der(include_bytes!("../tests/fixtures/cimd/ca.der"))
            .unwrap();
        let transport = PinnedTransport {
            test_root: Some(root),
        };
        let url = Url::parse(&format!(
            "https://client.example.org:{}/metadata.json",
            address.port()
        ))
        .unwrap();
        let response = transport
            .fetch(url, "client.example.org".into(), vec![address])
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.cache_control.as_ref().unwrap(),
            &["max-age=300", "No-Store"]
        );
        assert_eq!(response.age, 12);
        assert_eq!(
            cache_ttl(response.cache_control.as_deref(), response.age),
            None
        );
        let (sni, request) = server.await.unwrap();
        assert_eq!(sni, "client.example.org");
        assert!(request.starts_with("GET /metadata.json HTTP/1.1\r\n"));
        assert!(
            request.contains(&format!(
                "\r\nhost: client.example.org:{}\r\n",
                address.port()
            )) || request.contains(&format!(
                "\r\nHost: client.example.org:{}\r\n",
                address.port()
            ))
        );
    }
}
