use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::{Client, StatusCode, header};
use rsa::{BigUint, RsaPublicKey, traits::PublicKeyParts};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Semaphore};
use url::Url;

const AUTHORIZE_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const JWKS_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/certs";
const MAX_TOKEN_RESPONSE: usize = 64 * 1024;
const MAX_JWKS_RESPONSE: usize = 256 * 1024;
const MAX_KEYS: usize = 32;
const MAX_CACHE_AGE: Duration = Duration::from_secs(3600);
const UNKNOWN_KID_BACKOFF: Duration = Duration::from_secs(5);
const CLOCK_SKEW: i64 = 30;

#[derive(Clone)]
pub struct GoogleAdapter {
    client_id: String,
    client_secret: SecretSource,
    callback: String,
    http: Client,
    endpoints: Endpoints,
    cache: Arc<Mutex<KeyCache>>,
    requests: Arc<Semaphore>,
}

#[derive(Clone)]
struct Endpoints {
    authorize: String,
    token: String,
    jwks: String,
}
#[derive(Clone)]
enum SecretSource {
    Env(String),
    #[cfg(test)]
    Test(String),
}
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fresh_until: Instant,
    last_attempt: Option<Instant>,
}

pub struct VerifiedGoogleIdentity {
    subject: String,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
    verified_email: Option<String>,
    auth_time: Option<i64>,
}

impl fmt::Debug for VerifiedGoogleIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedGoogleIdentity([REDACTED])")
    }
}

impl VerifiedGoogleIdentity {
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn given_name(&self) -> Option<&str> {
        self.given_name.as_deref()
    }
    pub fn family_name(&self) -> Option<&str> {
        self.family_name.as_deref()
    }
    pub fn picture(&self) -> Option<&str> {
        self.picture.as_deref()
    }
    pub fn verified_email(&self) -> Option<&str> {
        self.verified_email.as_deref()
    }
    pub fn auth_time(&self) -> Option<i64> {
        self.auth_time
    }
    #[cfg(test)]
    pub(crate) fn for_test(
        subject: &str,
        name: Option<&str>,
        email: Option<&str>,
        auth_time: Option<i64>,
    ) -> Self {
        Self {
            subject: subject.into(),
            name: name.map(Into::into),
            given_name: None,
            family_name: None,
            picture: None,
            verified_email: email.map(Into::into),
            auth_time,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GoogleError {
    #[error("invalid Google adapter configuration")]
    InvalidConfiguration,
    #[error("Google client secret is unavailable")]
    SecretUnavailable,
    #[error("Google authorization input is invalid")]
    InvalidAuthorizationInput,
    #[error("Google token exchange failed")]
    TokenExchange,
    #[error("Google signing keys are unavailable")]
    KeysUnavailable,
    #[error("Google identity token is invalid")]
    InvalidIdentityToken,
}

struct GoogleSecret(String);
impl fmt::Debug for GoogleSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GoogleSecret([REDACTED])")
    }
}

impl GoogleAdapter {
    pub fn new(
        client_id: impl Into<String>,
        client_secret_env: impl Into<String>,
        issuer: &Url,
    ) -> Result<Self, GoogleError> {
        let client_id = client_id.into();
        let client_secret_env = client_secret_env.into();
        let loopback_http = issuer.scheme() == "http"
            && match issuer.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            };
        if client_id.is_empty()
            || client_secret_env.is_empty()
            || issuer.path() != "/"
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || issuer.host().is_none()
            || issuer.scheme() != "https" && !loopback_http
        {
            return Err(GoogleError::InvalidConfiguration);
        }
        let callback = issuer
            .join("federation/google/callback")
            .map_err(|_| GoogleError::InvalidConfiguration)?
            .to_string();
        let http = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| GoogleError::InvalidConfiguration)?;
        Ok(Self::with_parts(
            client_id,
            SecretSource::Env(client_secret_env),
            callback,
            http,
            Endpoints {
                authorize: AUTHORIZE_ENDPOINT.into(),
                token: TOKEN_ENDPOINT.into(),
                jwks: JWKS_ENDPOINT.into(),
            },
        ))
    }

    fn with_parts(
        client_id: String,
        client_secret: SecretSource,
        callback: String,
        http: Client,
        endpoints: Endpoints,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            callback,
            http,
            endpoints,
            cache: Arc::new(Mutex::new(KeyCache {
                keys: HashMap::new(),
                fresh_until: Instant::now(),
                last_attempt: None,
            })),
            requests: Arc::new(Semaphore::new(8)),
        }
    }

    pub fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        challenge: &str,
        select_account: bool,
    ) -> Result<Url, GoogleError> {
        if !valid_opaque(state) || !valid_opaque(nonce) || !valid_s256_challenge(challenge) {
            return Err(GoogleError::InvalidAuthorizationInput);
        }
        let mut url =
            Url::parse(&self.endpoints.authorize).map_err(|_| GoogleError::InvalidConfiguration)?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", &self.callback)
                .append_pair("response_type", "code")
                .append_pair("scope", "openid profile email")
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("access_type", "online");
            if select_account {
                q.append_pair("prompt", "select_account");
            }
        }
        Ok(url)
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedGoogleIdentity, GoogleError> {
        if !valid_opaque(code) || !valid_pkce_verifier(verifier) || !valid_opaque(expected_nonce) {
            return Err(GoogleError::InvalidAuthorizationInput);
        }
        let secret = self.secret()?;
        let permit = self
            .requests
            .try_acquire()
            .map_err(|_| GoogleError::TokenExchange)?;
        let response = self
            .http
            .post(&self.endpoints.token)
            .form(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", secret.0.as_str()),
                ("redirect_uri", self.callback.as_str()),
                ("grant_type", "authorization_code"),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|_| GoogleError::TokenExchange)?;
        if response.status() != StatusCode::OK {
            return Err(GoogleError::TokenExchange);
        }
        let body = bounded_body(response, MAX_TOKEN_RESPONSE)
            .await
            .map_err(|_| GoogleError::TokenExchange)?;
        let token: TokenResponse =
            serde_json::from_slice(&body).map_err(|_| GoogleError::TokenExchange)?;
        drop(permit);
        self.verify_id_token(&token.id_token, expected_nonce).await
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedGoogleIdentity, GoogleError> {
        if token.len() > MAX_TOKEN_RESPONSE || !valid_opaque(expected_nonce) {
            return Err(GoogleError::InvalidIdentityToken);
        }
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| GoogleError::InvalidIdentityToken)?;
        if header.alg != Algorithm::RS256
            || has_unsupported_crit(token)
            || header.typ.as_deref().is_some_and(|v| v != "JWT")
        {
            return Err(GoogleError::InvalidIdentityToken);
        }
        let kid = header.kid.ok_or(GoogleError::InvalidIdentityToken)?;
        if kid.is_empty() || kid.len() > 128 {
            return Err(GoogleError::InvalidIdentityToken);
        }
        let key = self.key(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.validate_nbf = true;
        validation.leeway = CLOCK_SKEW as u64;
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|_| GoogleError::InvalidIdentityToken)?
            .claims;
        validate_claims(claims, &self.client_id, expected_nonce, unix_now())
    }

    fn secret(&self) -> Result<GoogleSecret, GoogleError> {
        let value = match &self.client_secret {
            SecretSource::Env(name) => std::env::var(name).ok(),
            #[cfg(test)]
            SecretSource::Test(value) => Some(value.clone()),
        };
        value
            .filter(|v| !v.is_empty())
            .map(GoogleSecret)
            .ok_or(GoogleError::SecretUnavailable)
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, GoogleError> {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        if now < cache.fresh_until
            && let Some(key) = cache.keys.get(kid)
        {
            return Ok(key.clone());
        }
        if cache
            .last_attempt
            .is_some_and(|attempt| now.duration_since(attempt) < UNKNOWN_KID_BACKOFF)
        {
            return Err(GoogleError::KeysUnavailable);
        }
        cache.last_attempt = Some(now);
        let (keys, freshness) = self.fetch_keys().await?;
        cache.keys = keys;
        cache.fresh_until = Instant::now() + freshness;
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or(GoogleError::KeysUnavailable)
    }

    async fn fetch_keys(&self) -> Result<(HashMap<String, DecodingKey>, Duration), GoogleError> {
        let _permit = self
            .requests
            .try_acquire()
            .map_err(|_| GoogleError::KeysUnavailable)?;
        let response = self
            .http
            .get(&self.endpoints.jwks)
            .send()
            .await
            .map_err(|_| GoogleError::KeysUnavailable)?;
        if response.status() != StatusCode::OK {
            return Err(GoogleError::KeysUnavailable);
        }
        let freshness = cache_freshness(response.headers());
        let body = bounded_body(response, MAX_JWKS_RESPONSE)
            .await
            .map_err(|_| GoogleError::KeysUnavailable)?;
        let jwks: JwkSet =
            serde_json::from_slice(&body).map_err(|_| GoogleError::KeysUnavailable)?;
        if jwks.keys.is_empty() || jwks.keys.len() > MAX_KEYS {
            return Err(GoogleError::KeysUnavailable);
        }
        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            if jwk.kty != "RSA"
                || jwk.kid.is_empty()
                || jwk.kid.len() > 128
                || jwk.alg.as_deref().is_some_and(|v| v != "RS256")
                || jwk.use_.as_deref().is_some_and(|v| v != "sig")
                || jwk
                    .key_ops
                    .as_ref()
                    .is_some_and(|ops| ops.is_empty() || ops.iter().any(|op| op != "verify"))
            {
                return Err(GoogleError::KeysUnavailable);
            }
            let n = URL_SAFE_NO_PAD
                .decode(&jwk.n)
                .map_err(|_| GoogleError::KeysUnavailable)?;
            let e = URL_SAFE_NO_PAD
                .decode(&jwk.e)
                .map_err(|_| GoogleError::KeysUnavailable)?;
            if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 8 {
                return Err(GoogleError::KeysUnavailable);
            }
            let rsa = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
                .map_err(|_| GoogleError::KeysUnavailable)?;
            if !(2048..=8192).contains(&rsa.n().bits())
                || keys
                    .insert(
                        jwk.kid,
                        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                            .map_err(|_| GoogleError::KeysUnavailable)?,
                    )
                    .is_some()
            {
                return Err(GoogleError::KeysUnavailable);
            }
        }
        Ok((keys, freshness))
    }
}

async fn bounded_body(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len() + chunk.len() > maximum {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn cache_freshness(headers: &header::HeaderMap) -> Duration {
    let directives = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if directives.split(',').any(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "no-cache" | "no-store"
        )
    }) {
        return Duration::ZERO;
    }
    let max_age = directives
        .split(',')
        .find_map(|v| {
            v.trim()
                .to_ascii_lowercase()
                .strip_prefix("max-age=")?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0)
        .min(MAX_CACHE_AGE.as_secs());
    let age = headers
        .get(header::AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    Duration::from_secs(max_age.saturating_sub(age))
}
fn valid_opaque(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && value.bytes().all(|b| b.is_ascii_graphic())
}
fn valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}
fn valid_s256_challenge(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value)
}
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn has_unsupported_crit(token: &str) -> bool {
    let Some(encoded) = token.split('.').next() else {
        return true;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return true;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return true;
    };
    value
        .get("crit")
        .is_some_and(|crit| crit.as_array().is_none_or(|items| !items.is_empty()))
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    n: String,
    e: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    key_ops: Option<Vec<String>>,
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    azp: Option<String>,
    exp: i64,
    iat: i64,
    nbf: Option<i64>,
    nonce: String,
    auth_time: Option<i64>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
    email: Option<String>,
    email_verified: Option<BoolClaim>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
#[derive(Deserialize)]
#[serde(untagged)]
enum BoolClaim {
    Bool(bool),
    Text(String),
}
impl BoolClaim {
    fn is_true(&self) -> bool {
        matches!(self, Self::Bool(true)) || matches!(self, Self::Text(v) if v == "true")
    }
}

fn validate_claims(
    claims: Claims,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<VerifiedGoogleIdentity, GoogleError> {
    if !matches!(
        claims.iss.as_str(),
        "accounts.google.com" | "https://accounts.google.com"
    ) || claims.sub.is_empty()
        || claims.sub.len() > 255
        || !claims.sub.is_ascii()
        || claims.nonce != nonce
        || claims.exp.saturating_add(CLOCK_SKEW) < now
        || claims.iat < 0
        || claims.iat > now + CLOCK_SKEW
        || claims.nbf.is_some_and(|v| v > now + CLOCK_SKEW)
        || claims
            .auth_time
            .is_some_and(|v| v < 0 || v > now + CLOCK_SKEW)
    {
        return Err(GoogleError::InvalidIdentityToken);
    }
    let (aud_ok, multiple) = match &claims.aud {
        Audience::One(v) => (v == client_id, false),
        Audience::Many(v) => (v.iter().any(|a| a == client_id), v.len() > 1),
    };
    if !aud_ok
        || claims.azp.as_deref().is_some_and(|v| v != client_id)
        || multiple && claims.azp.as_deref() != Some(client_id)
    {
        return Err(GoogleError::InvalidIdentityToken);
    }
    let verified_email = if claims
        .email_verified
        .as_ref()
        .is_some_and(BoolClaim::is_true)
    {
        claims.email.filter(|v| !v.is_empty())
    } else {
        None
    };
    Ok(VerifiedGoogleIdentity {
        subject: claims.sub,
        name: claims.name,
        given_name: claims.given_name,
        family_name: claims.family_name,
        picture: claims.picture,
        verified_email,
        auth_time: claims.auth_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialStore, Database};
    use axum::{
        Router,
        body::Body,
        http::{Response, StatusCode},
        routing::get,
    };
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey};
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::net::TcpListener;

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/keys")
                .join(name),
        )
        .unwrap()
    }
    fn jwk(name: &str, kid: &str) -> Value {
        let pem = String::from_utf8(fixture(&format!("{name}-public.pem"))).unwrap();
        let key = RsaPublicKey::from_public_key_pem(&pem).unwrap();
        json!({"kty":"RSA","kid":kid,"use":"sig","alg":"RS256","key_ops":["verify"],"n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())})
    }
    fn claims() -> Value {
        let now = unix_now();
        json!({"iss":"https://accounts.google.com","sub":"google-subject","aud":"client-1","exp":now+300,"iat":now,"nonce":"nonce-value","name":"Person","email":"person@example.test","email_verified":true})
    }
    fn sign(name: &str, kid: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        header.typ = Some("JWT".into());
        jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(&fixture(&format!("{name}-private.pem"))).unwrap(),
        )
        .unwrap()
    }
    fn sign_header(header: Value, claims: &Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let message = format!("{header}.{claims}");
        let signature = jsonwebtoken::crypto::sign(
            message.as_bytes(),
            &EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap(),
            Algorithm::RS256,
        )
        .unwrap();
        format!("{message}.{signature}")
    }
    fn adapter_with_key() -> GoogleAdapter {
        let mut adapter = GoogleAdapter::new(
            "client-1",
            "UNSET_GOOGLE_SECRET",
            &Url::parse("https://auth.example/").unwrap(),
        )
        .unwrap();
        adapter.endpoints.jwks = "http://127.0.0.1:1/certs".into();
        let public = jwk("active", "active");
        let n = public["n"].as_str().unwrap();
        let e = public["e"].as_str().unwrap();
        adapter.cache.try_lock().unwrap().keys.insert(
            "active".into(),
            DecodingKey::from_rsa_components(n, e).unwrap(),
        );
        adapter.cache.try_lock().unwrap().fresh_until = Instant::now() + Duration::from_secs(60);
        adapter
    }

    #[tokio::test]
    async fn authorization_url_is_fixed_encoded_and_does_not_claim_reauthentication() {
        let adapter = adapter_with_key();
        let url = adapter
            .authorization_url(
                "state/value",
                "nonce-value",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                true,
            )
            .unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://accounts.google.com"
        );
        let pairs = url.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(pairs.get("scope").unwrap(), "openid profile email");
        assert_eq!(pairs.get("access_type").unwrap(), "online");
        assert_eq!(pairs.get("prompt").unwrap(), "select_account");
        assert!(!url.as_str().contains("prompt=login"));
        assert_eq!(
            pairs.get("redirect_uri").unwrap(),
            "https://auth.example/federation/google/callback"
        );
    }

    #[tokio::test]
    async fn verifies_signed_identity_and_filters_unverified_email() {
        let adapter = adapter_with_key();
        let identity = adapter
            .verify_id_token(&sign("active", "active", &claims()), "nonce-value")
            .await
            .unwrap();
        assert_eq!(identity.subject(), "google-subject");
        assert_eq!(identity.verified_email(), Some("person@example.test"));
        assert_eq!(identity.auth_time(), None);
        assert!(!format!("{identity:?}").contains("google-subject"));
        let mut false_email = claims();
        false_email["email_verified"] = json!("false");
        let identity = adapter
            .verify_id_token(&sign("active", "active", &false_email), "nonce-value")
            .await
            .unwrap();
        assert_eq!(identity.verified_email(), None);
        let mut string_email = claims();
        string_email["email_verified"] = json!("true");
        assert_eq!(
            adapter
                .verify_id_token(&sign("active", "active", &string_email), "nonce-value")
                .await
                .unwrap()
                .verified_email(),
            Some("person@example.test")
        );
        let mut with_auth_time = claims();
        with_auth_time["auth_time"] = json!(unix_now() - 120);
        assert_eq!(
            adapter
                .verify_id_token(&sign("active", "active", &with_auth_time), "nonce-value")
                .await
                .unwrap()
                .auth_time(),
            with_auth_time["auth_time"].as_i64()
        );
        let mut optional = claims();
        optional.as_object_mut().unwrap().remove("name");
        optional.as_object_mut().unwrap().remove("email");
        optional.as_object_mut().unwrap().remove("email_verified");
        assert!(
            adapter
                .verify_id_token(&sign("active", "active", &optional), "nonce-value")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_signature_header_and_required_claim_failures() {
        let adapter = adapter_with_key();
        assert!(
            adapter
                .verify_id_token(&sign("next", "active", &claims()), "nonce-value")
                .await
                .is_err()
        );
        assert!(
            adapter
                .verify_id_token(&sign("active", "unknown", &claims()), "nonce-value")
                .await
                .is_err()
        );
        let mut hs = Header::new(Algorithm::HS256);
        hs.kid = Some("active".into());
        hs.typ = Some("JWT".into());
        let token =
            jsonwebtoken::encode(&hs, &claims(), &EncodingKey::from_secret(b"not-rsa")).unwrap();
        assert!(
            adapter
                .verify_id_token(&token, "nonce-value")
                .await
                .is_err()
        );
        let mut no_type = Header::new(Algorithm::RS256);
        no_type.kid = Some("active".into());
        no_type.typ = None;
        let token = jsonwebtoken::encode(
            &no_type,
            &claims(),
            &EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap(),
        )
        .unwrap();
        assert!(
            adapter_with_key()
                .verify_id_token(&token, "nonce-value")
                .await
                .is_ok()
        );
        let critical = sign_header(
            json!({"alg":"RS256","kid":"active","typ":"JWT","crit":["unknown"]}),
            &claims(),
        );
        assert!(
            adapter
                .verify_id_token(&critical, "nonce-value")
                .await
                .is_err()
        );
        let missing_kid = sign_header(json!({"alg":"RS256","typ":"JWT"}), &claims());
        assert!(
            adapter
                .verify_id_token(&missing_kid, "nonce-value")
                .await
                .is_err()
        );
        let mut wrong_type = Header::new(Algorithm::RS256);
        wrong_type.kid = Some("active".into());
        wrong_type.typ = Some("at+jwt".into());
        let token = jsonwebtoken::encode(
            &wrong_type,
            &claims(),
            &EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap(),
        )
        .unwrap();
        assert!(
            adapter
                .verify_id_token(&token, "nonce-value")
                .await
                .is_err()
        );
        for missing in ["iss", "sub", "aud", "exp", "iat", "nonce"] {
            let mut value = claims();
            value.as_object_mut().unwrap().remove(missing);
            assert!(
                adapter
                    .verify_id_token(&sign("active", "active", &value), "nonce-value")
                    .await
                    .is_err(),
                "{missing}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_issuer_audience_azp_nonce_and_time_failures() {
        let adapter = adapter_with_key();
        for (field, value) in [
            ("iss", json!("https://evil.example")),
            ("aud", json!("other")),
            ("nonce", json!("other")),
            ("exp", json!(unix_now() - 31)),
            ("iat", json!(unix_now() + 120)),
        ] {
            let mut bad = claims();
            bad[field] = value;
            assert!(
                adapter
                    .verify_id_token(&sign("active", "active", &bad), "nonce-value")
                    .await
                    .is_err(),
                "{field}"
            );
        }
        let mut multi = claims();
        multi["aud"] = json!(["client-1", "other"]);
        assert!(
            adapter
                .verify_id_token(&sign("active", "active", &multi), "nonce-value")
                .await
                .is_err()
        );
        multi["azp"] = json!("client-1");
        assert!(
            adapter
                .verify_id_token(&sign("active", "active", &multi), "nonce-value")
                .await
                .is_ok()
        );
        multi["azp"] = json!("other");
        assert!(
            adapter
                .verify_id_token(&sign("active", "active", &multi), "nonce-value")
                .await
                .is_err()
        );
        let mut auth_time = claims();
        auth_time["auth_time"] = json!(unix_now() + 120);
        assert!(
            adapter
                .verify_id_token(&sign("active", "active", &auth_time), "nonce-value")
                .await
                .is_err()
        );
        let mut future_nbf = claims();
        future_nbf["nbf"] = json!(unix_now() + 120);
        assert!(
            adapter
                .verify_id_token(&sign("active", "active", &future_nbf), "nonce-value")
                .await
                .is_err()
        );
    }

    async fn serve_jwks(
        body: Vec<u8>,
        counter: Arc<AtomicUsize>,
        delay: Duration,
        redirect: bool,
    ) -> String {
        let app = Router::new()
            .route(
                "/certs",
                get(move || {
                    let body = body.clone();
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if redirect {
                            Response::builder()
                                .status(StatusCode::FOUND)
                                .header("location", "/other")
                                .body(Body::empty())
                                .unwrap()
                        } else {
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("cache-control", "max-age=600")
                                .body(Body::from(body))
                                .unwrap()
                        }
                    }
                }),
            )
            .route("/other", get(|| async { "unexpected" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}/certs")
    }
    async fn serve_mutable_jwks(
        state: Arc<std::sync::Mutex<(StatusCode, Vec<u8>)>>,
        counter: Arc<AtomicUsize>,
    ) -> String {
        let app = Router::new().route(
            "/certs",
            get(move || {
                let state = state.clone();
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = state.lock().unwrap().clone();
                    Response::builder()
                        .status(status)
                        .header("cache-control", "max-age=600")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}/certs")
    }
    async fn serve_token(body: Vec<u8>, delay: Duration, redirect: bool) -> String {
        let app = Router::new()
            .route(
                "/token",
                axum::routing::post(move || {
                    let body = body.clone();
                    async move {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if redirect {
                            Response::builder()
                                .status(StatusCode::FOUND)
                                .header("location", "/other")
                                .body(Body::empty())
                                .unwrap()
                        } else {
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(body))
                                .unwrap()
                        }
                    }
                }),
            )
            .route("/other", axum::routing::post(|| async { "unexpected" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}/token")
    }
    async fn serve_successful_token(
        id_token: String,
        captured: Arc<std::sync::Mutex<Option<HashMap<String, String>>>>,
    ) -> String {
        let app = Router::new().route(
            "/token",
            axum::routing::post(
                move |axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>| {
                    let id_token = id_token.clone();
                    let captured = captured.clone();
                    async move {
                        *captured.lock().unwrap() = Some(form);
                        axum::Json(json!({"id_token": id_token}))
                    }
                },
            ),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}/token")
    }
    async fn serve_barrier_google(
        id_token: String,
    ) -> (
        String,
        String,
        Arc<tokio::sync::Notify>,
        Arc<Semaphore>,
        Arc<AtomicUsize>,
    ) {
        let arrivals = Arc::new(AtomicUsize::new(0));
        let eight_arrived = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let jwks_fetches = Arc::new(AtomicUsize::new(0));
        let token_route = {
            let arrivals = arrivals.clone();
            let eight_arrived = eight_arrived.clone();
            let release = release.clone();
            move || {
                let id_token = id_token.clone();
                let arrivals = arrivals.clone();
                let eight_arrived = eight_arrived.clone();
                let release = release.clone();
                async move {
                    if arrivals.fetch_add(1, Ordering::SeqCst) + 1 == 8 {
                        eight_arrived.notify_one();
                    }
                    let _release = release.acquire().await.unwrap();
                    axum::Json(json!({"id_token": id_token}))
                }
            }
        };
        let jwks_route = {
            let jwks_fetches = jwks_fetches.clone();
            move || {
                let jwks_fetches = jwks_fetches.clone();
                async move {
                    jwks_fetches.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header("cache-control", "max-age=600")
                        .body(Body::from(
                            serde_json::to_vec(&json!({"keys":[jwk("active", "active")]})).unwrap(),
                        ))
                        .unwrap()
                }
            }
        };
        let app = Router::new()
            .route("/token", axum::routing::post(token_route))
            .route("/certs", get(jwks_route));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            format!("http://{address}/token"),
            format!("http://{address}/certs"),
            eight_arrived,
            release,
            jwks_fetches,
        )
    }
    async fn http_adapter(jwks: String, timeout: Duration) -> GoogleAdapter {
        let http = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .unwrap();
        GoogleAdapter::with_parts(
            "client-1".into(),
            SecretSource::Test("test-secret".into()),
            "http://127.0.0.1/callback".into(),
            http,
            Endpoints {
                authorize: "http://127.0.0.1/authorize".into(),
                token: "http://127.0.0.1/token".into(),
                jwks,
            },
        )
    }

    #[tokio::test]
    async fn jwks_cache_reuses_and_coalesces_simultaneous_misses() {
        let counter = Arc::new(AtomicUsize::new(0));
        let body = serde_json::to_vec(&json!({"keys":[jwk("active", "active")]})).unwrap();
        let endpoint = serve_jwks(body, counter.clone(), Duration::from_millis(20), false).await;
        let adapter = http_adapter(endpoint, Duration::from_secs(1)).await;
        let token = sign("active", "active", &claims());
        let (a, b) = tokio::join!(
            adapter.verify_id_token(&token, "nonce-value"),
            adapter.verify_id_token(&token, "nonce-value")
        );
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(adapter.verify_id_token(&token, "nonce-value").await.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(
            adapter
                .verify_id_token(&sign("active", "missing", &claims()), "nonce-value")
                .await
                .is_err()
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_cache_rotates_and_failed_refresh_is_throttled_then_recovers() {
        let active_body = serde_json::to_vec(&json!({"keys":[jwk("active", "active")]})).unwrap();
        let state = Arc::new(std::sync::Mutex::new((StatusCode::OK, active_body)));
        let counter = Arc::new(AtomicUsize::new(0));
        let endpoint = serve_mutable_jwks(state.clone(), counter.clone()).await;
        let adapter = http_adapter(endpoint, Duration::from_secs(1)).await;
        assert!(
            adapter
                .verify_id_token(&sign("active", "active", &claims()), "nonce-value")
                .await
                .is_ok()
        );

        *state.lock().unwrap() = (
            StatusCode::OK,
            serde_json::to_vec(&json!({"keys":[jwk("next", "next")]})).unwrap(),
        );
        {
            let mut cache = adapter.cache.lock().await;
            cache.fresh_until = Instant::now();
            cache.last_attempt = None;
        }
        assert!(
            adapter
                .verify_id_token(&sign("next", "next", &claims()), "nonce-value")
                .await
                .is_ok()
        );

        *state.lock().unwrap() = (StatusCode::INTERNAL_SERVER_ERROR, Vec::new());
        {
            let mut cache = adapter.cache.lock().await;
            cache.fresh_until = Instant::now();
            cache.last_attempt = None;
        }
        assert!(
            adapter
                .verify_id_token(&sign("next", "next", &claims()), "nonce-value")
                .await
                .is_err()
        );
        let attempts = counter.load(Ordering::SeqCst);
        assert!(
            adapter
                .verify_id_token(&sign("next", "next", &claims()), "nonce-value")
                .await
                .is_err()
        );
        assert_eq!(counter.load(Ordering::SeqCst), attempts);

        *state.lock().unwrap() = (
            StatusCode::OK,
            serde_json::to_vec(&json!({"keys":[jwk("next", "next")]})).unwrap(),
        );
        adapter.cache.lock().await.last_attempt = Some(Instant::now() - UNKNOWN_KID_BACKOFF);
        assert!(
            adapter
                .verify_id_token(&sign("next", "next", &claims()), "nonce-value")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn jwks_rejects_redirect_timeout_oversize_and_malformed_keys() {
        for (body, delay, redirect) in [
            (b"{}".to_vec(), Duration::ZERO, true),
            (b"{}".to_vec(), Duration::from_millis(50), false),
            (vec![b'x'; MAX_JWKS_RESPONSE + 1], Duration::ZERO, false),
            (
                serde_json::to_vec(&json!({"keys":[jwk("active", "dup"),jwk("active", "dup")]}))
                    .unwrap(),
                Duration::ZERO,
                false,
            ),
        ] {
            let endpoint = serve_jwks(body, Arc::new(AtomicUsize::new(0)), delay, redirect).await;
            let adapter = http_adapter(endpoint, Duration::from_millis(25)).await;
            assert!(
                adapter
                    .verify_id_token(&sign("active", "active", &claims()), "nonce-value")
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn token_exchange_rejects_redirect_timeout_oversize_and_malformed_json() {
        for (body, delay, redirect) in [
            (b"{}".to_vec(), Duration::ZERO, true),
            (b"{}".to_vec(), Duration::from_millis(50), false),
            (vec![b'x'; MAX_TOKEN_RESPONSE + 1], Duration::ZERO, false),
            (b"not-json".to_vec(), Duration::ZERO, false),
        ] {
            let endpoint = serve_token(body, delay, redirect).await;
            let mut adapter =
                http_adapter("http://127.0.0.1:1/certs".into(), Duration::from_millis(25)).await;
            adapter.endpoints.token = endpoint;
            assert!(
                adapter
                    .exchange_code(
                        "exact-code",
                        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        "nonce-value",
                    )
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn token_exchange_sends_exact_transaction_binding_and_returns_verified_identity() {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let endpoint =
            serve_successful_token(sign("active", "active", &claims()), captured.clone()).await;
        let mut adapter =
            http_adapter("http://127.0.0.1:1/certs".into(), Duration::from_secs(1)).await;
        adapter.endpoints.token = endpoint;
        let public = jwk("active", "active");
        adapter.cache.lock().await.keys.insert(
            "active".into(),
            DecodingKey::from_rsa_components(
                public["n"].as_str().unwrap(),
                public["e"].as_str().unwrap(),
            )
            .unwrap(),
        );
        adapter.cache.lock().await.fresh_until = Instant::now() + Duration::from_secs(60);
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let identity = adapter
            .exchange_code("exact-code", verifier, "nonce-value")
            .await
            .unwrap();
        assert_eq!(identity.subject(), "google-subject");
        let form = captured.lock().unwrap().take().unwrap();
        assert_eq!(form.get("code").unwrap(), "exact-code");
        assert_eq!(form.get("client_id").unwrap(), "client-1");
        assert!(
            form.get("client_secret")
                .is_some_and(|value| value == "test-secret"),
            "token request must contain the configured secret"
        );
        assert_eq!(
            form.get("redirect_uri").unwrap(),
            "http://127.0.0.1/callback"
        );
        assert_eq!(form.get("grant_type").unwrap(), "authorization_code");
        assert_eq!(form.get("code_verifier").unwrap(), verifier);
        assert_eq!(form.len(), 6);
    }

    #[tokio::test]
    async fn eight_cold_cache_exchanges_release_capacity_for_one_coalesced_jwks_fetch() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (token, jwks, eight_arrived, release, jwks_fetches) =
                serve_barrier_google(sign("active", "active", &claims())).await;
            let mut adapter = http_adapter(jwks, Duration::from_secs(1)).await;
            adapter.endpoints.token = token;
            let mut tasks = Vec::new();
            for index in 0..8 {
                let adapter = adapter.clone();
                tasks.push(tokio::spawn(async move {
                    adapter
                        .exchange_code(
                            &format!("code-{index}"),
                            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                            "nonce-value",
                        )
                        .await
                }));
            }
            eight_arrived.notified().await;
            assert!(
                adapter
                    .exchange_code(
                        "saturated-request",
                        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        "nonce-value",
                    )
                    .await
                    .is_err(),
                "a ninth request must be rejected while all permits are occupied"
            );
            release.add_permits(8);
            for task in tasks {
                assert!(task.await.unwrap().is_ok());
            }
            assert_eq!(jwks_fetches.load(Ordering::SeqCst), 1);
        })
        .await
        .expect("cold-cache exchange regression timed out");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn only_verified_identity_crosses_database_session_boundary(pool: PgPool) {
        let url = std::env::var("DATABASE_URL").unwrap();
        assert!(
            url == std::env::var("ERI_TEST_DATABASE_URL").unwrap(),
            "database tests require isolated URL"
        );
        let adapter = adapter_with_key();
        let verified = adapter
            .verify_id_token(&sign("active", "active", &claims()), "nonce-value")
            .await
            .unwrap();
        let database = Database::from_pool(pool.clone(), Duration::from_secs(1));
        let first = database
            .find_or_create_verified_google_identity(&verified)
            .await
            .unwrap();
        let second = database
            .find_or_create_verified_google_identity(&verified)
            .await
            .unwrap();
        assert_eq!(first, second);
        let mut other_claims = claims();
        other_claims["sub"] = json!("different-google-subject");
        let other = adapter
            .verify_id_token(&sign("active", "active", &other_claims), "nonce-value")
            .await
            .unwrap();
        let other_user = database
            .find_or_create_verified_google_identity(&other)
            .await
            .unwrap();
        assert_ne!(first, other_user);
        let session = CredentialStore::new(pool)
            .create_provider_session(first, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(session.expose().len(), 43);
    }
}
