use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectKind {
    Exact,
    NativeLoopback,
}
#[derive(Clone, Debug)]
pub struct RegisteredRedirect {
    uri: String,
    kind: RedirectKind,
}
#[derive(Clone, Debug)]
pub struct FirstPartyClient {
    id: String,
    display_name: String,
    redirects: Vec<RegisteredRedirect>,
    scopes: BTreeSet<String>,
    resources: BTreeSet<String>,
    default_resource: Option<String>,
    browser_origins: BTreeSet<String>,
    post_logout_redirects: BTreeSet<String>,
}
#[derive(Clone, Debug, Default)]
pub struct ClientRegistry {
    clients: HashMap<String, FirstPartyClient>,
    userinfo_resource: Option<String>,
}
#[derive(Clone, Debug)]
pub struct AuthorizationRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub response_type: &'a str,
    pub code_challenge_method: &'a str,
    pub code_challenge: &'a str,
    pub scopes: &'a [&'a str],
    pub resource: Option<&'a str>,
}
#[derive(Clone, Debug)]
pub struct PendingAuthorizationGrant {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    resource: String,
    code_challenge: String,
}
#[derive(Clone, Debug)]
pub struct ValidatedAuthorizationGrant {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    resource: String,
    code_challenge: String,
    issue_refresh_token: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("invalid client declaration")]
    InvalidClientDeclaration,
    #[error("unknown client")]
    UnknownClient,
    #[error("unsupported response type")]
    UnsupportedResponseType,
    #[error("unsupported PKCE method")]
    UnsupportedPkceMethod,
    #[error("invalid PKCE value")]
    InvalidPkce,
    #[error("redirect URI is invalid")]
    InvalidRedirect,
    #[error("scope is not allowed")]
    InvalidScope,
    #[error("resource is not allowed")]
    InvalidResource,
    #[error("offline access requires explicit consent")]
    ConsentRequired,
}

impl RegisteredRedirect {
    pub fn new(uri: impl Into<String>, kind: RedirectKind) -> Result<Self, OAuthError> {
        let uri = uri.into();
        let parsed = safe_redirect(&uri).map_err(|_| OAuthError::InvalidClientDeclaration)?;
        if kind == RedirectKind::NativeLoopback
            && (parsed.scheme() != "http" || loopback_parts(&uri).is_none())
        {
            return Err(OAuthError::InvalidClientDeclaration);
        }
        Ok(Self { uri, kind })
    }
}

impl FirstPartyClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        redirects: Vec<RegisteredRedirect>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
        resources: impl IntoIterator<Item = impl Into<String>>,
        default_resource: Option<String>,
        browser_origins: impl IntoIterator<Item = impl Into<String>>,
        post_logout_redirects: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, OAuthError> {
        let id = id.into();
        let display_name = display_name.into();
        let scopes = scopes.into_iter().map(Into::into).collect::<BTreeSet<_>>();
        let resources = resources
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let browser_origins = browser_origins
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        let post_logout_redirects = post_logout_redirects
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>();
        if id.is_empty()
            || display_name.trim().is_empty()
            || redirects.is_empty()
            || scopes.is_empty()
            || scopes.iter().any(|s| !valid_scope_token(s))
        {
            return Err(OAuthError::InvalidClientDeclaration);
        }
        if default_resource
            .as_ref()
            .is_some_and(|r| !resources.contains(r))
            || resources
                .iter()
                .any(|r| safe_security_identifier(r).is_err())
            || browser_origins.iter().any(|o| {
                safe_url(o).is_err()
                    || Url::parse(o).is_ok_and(|u| u.path() != "/" || u.query().is_some())
            })
            || post_logout_redirects
                .iter()
                .any(|r| safe_redirect(r).is_err())
        {
            return Err(OAuthError::InvalidClientDeclaration);
        }
        Ok(Self {
            id,
            display_name,
            redirects,
            scopes,
            resources,
            default_resource,
            browser_origins,
            post_logout_redirects,
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    pub fn browser_origins(&self) -> &BTreeSet<String> {
        &self.browser_origins
    }
}

impl ClientRegistry {
    pub fn new(clients: Vec<FirstPartyClient>) -> Result<Self, OAuthError> {
        Self::build(clients, None)
    }
    pub fn with_issuer(clients: Vec<FirstPartyClient>, issuer: &Url) -> Result<Self, OAuthError> {
        let resource = issuer
            .join("userinfo")
            .map_err(|_| OAuthError::InvalidClientDeclaration)?
            .to_string();
        Self::build(clients, Some(resource))
    }
    fn build(
        clients: Vec<FirstPartyClient>,
        userinfo_resource: Option<String>,
    ) -> Result<Self, OAuthError> {
        let mut map = HashMap::new();
        for client in clients {
            if map.insert(client.id.clone(), client).is_some() {
                return Err(OAuthError::InvalidClientDeclaration);
            }
        }
        Ok(Self {
            clients: map,
            userinfo_resource,
        })
    }
    pub fn trusted_redirect(&self, client_id: &str, uri: &str) -> bool {
        self.clients
            .get(client_id)
            .is_some_and(|c| c.redirects.iter().any(|r| redirect_matches(r, uri)))
    }
    pub fn valid_post_logout_redirect(&self, client_id: &str, uri: &str) -> bool {
        self.clients.get(client_id).is_some_and(|c| {
            c.post_logout_redirects
                .iter()
                .any(|r| r.as_bytes() == uri.as_bytes())
        })
    }
    pub fn validate_pending(
        &self,
        request: AuthorizationRequest<'_>,
    ) -> Result<PendingAuthorizationGrant, OAuthError> {
        self.validate_pending_parts(
            request.client_id,
            request.redirect_uri,
            request.response_type,
            request.code_challenge_method,
            request.code_challenge,
            request.scopes,
            request.resource,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn validate_pending_parts(
        &self,
        client_id: &str,
        redirect_uri: &str,
        response_type: &str,
        method: &str,
        challenge: &str,
        scopes: &[&str],
        resource: Option<&str>,
    ) -> Result<PendingAuthorizationGrant, OAuthError> {
        let client = self
            .clients
            .get(client_id)
            .ok_or(OAuthError::UnknownClient)?;
        if response_type != "code" {
            return Err(OAuthError::UnsupportedResponseType);
        }
        if method != "S256" {
            return Err(OAuthError::UnsupportedPkceMethod);
        }
        validate_pkce_challenge(challenge)?;
        if !client
            .redirects
            .iter()
            .any(|r| redirect_matches(r, redirect_uri))
        {
            return Err(OAuthError::InvalidRedirect);
        }
        let requested = scopes
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>();
        if requested.len() != scopes.len()
            || requested.is_empty()
            || requested.iter().any(|s| !valid_scope_token(s))
            || !requested.is_subset(&client.scopes)
        {
            return Err(OAuthError::InvalidScope);
        }
        let resource = resource
            .map(str::to_owned)
            .or_else(|| client.default_resource.clone())
            .or_else(|| {
                requested
                    .contains("openid")
                    .then(|| self.userinfo_resource.clone())
                    .flatten()
            })
            .ok_or(OAuthError::InvalidResource)?;
        if !(client.resources.contains(&resource)
            || requested.contains("openid")
                && self.userinfo_resource.as_deref() == Some(resource.as_str()))
        {
            return Err(OAuthError::InvalidResource);
        }
        Ok(PendingAuthorizationGrant {
            client_id: client.id.clone(),
            redirect_uri: redirect_uri.into(),
            scopes: requested.into_iter().collect(),
            resource,
            code_challenge: challenge.into(),
        })
    }
    pub fn revalidate_pending(
        &self,
        p: &PendingAuthorizationGrant,
    ) -> Result<PendingAuthorizationGrant, OAuthError> {
        let scopes = p.scopes.iter().map(String::as_str).collect::<Vec<_>>();
        self.validate_pending_parts(
            &p.client_id,
            &p.redirect_uri,
            "code",
            "S256",
            &p.code_challenge,
            &scopes,
            Some(&p.resource),
        )
    }
}

impl PendingAuthorizationGrant {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
    pub(crate) fn approve(self, consent: bool) -> Result<ValidatedAuthorizationGrant, OAuthError> {
        let refresh = self.scopes.iter().any(|s| s == "offline_access");
        if refresh && !consent {
            return Err(OAuthError::ConsentRequired);
        }
        Ok(ValidatedAuthorizationGrant {
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            scopes: self.scopes,
            resource: self.resource,
            code_challenge: self.code_challenge,
            issue_refresh_token: refresh,
        })
    }
}
impl ValidatedAuthorizationGrant {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
    pub fn issue_refresh_token(&self) -> bool {
        self.issue_refresh_token
    }
}

pub fn s256_challenge(verifier: &str) -> Result<String, OAuthError> {
    validate_pkce_verifier(verifier)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}

pub fn verify_s256(verifier: &str, expected: &str) -> bool {
    let Ok(actual) = s256_challenge(verifier) else {
        return false;
    };
    validate_pkce_challenge(expected).is_ok() && actual.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn validate_pkce_verifier(value: &str) -> Result<(), OAuthError> {
    if (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        Ok(())
    } else {
        Err(OAuthError::InvalidPkce)
    }
}
fn validate_pkce_challenge(value: &str) -> Result<(), OAuthError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(OAuthError::InvalidPkce);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| OAuthError::InvalidPkce)?;
    if decoded.len() == 32 && URL_SAFE_NO_PAD.encode(&decoded) == value {
        Ok(())
    } else {
        Err(OAuthError::InvalidPkce)
    }
}
fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == b'!' || (b'#'..=b'[').contains(&b) || (b']'..=b'~').contains(&b))
}
fn safe_url(raw: &str) -> Result<Url, ()> {
    let url = Url::parse(raw).map_err(|_| ())?;
    if url.cannot_be_a_base()
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        Err(())
    } else {
        Ok(url)
    }
}
fn safe_redirect(raw: &str) -> Result<Url, ()> {
    let url = Url::parse(raw).map_err(|_| ())?;
    if url.scheme().is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        Err(())
    } else {
        Ok(url)
    }
}
fn safe_security_identifier(raw: &str) -> Result<(), ()> {
    let url = safe_url(raw)?;
    if url.scheme() == "https" && url.query().is_none() {
        Ok(())
    } else {
        Err(())
    }
}
fn redirect_matches(registered: &RegisteredRedirect, actual: &str) -> bool {
    if safe_redirect(actual).is_err() {
        return false;
    }
    if registered.uri.as_bytes() == actual.as_bytes() {
        return true;
    }
    if registered.kind == RedirectKind::Exact {
        return false;
    }
    let Some((registered_host, registered_suffix)) = loopback_parts(&registered.uri) else {
        return false;
    };
    let Some((actual_host, actual_suffix)) = loopback_parts(actual) else {
        return false;
    };
    registered_host == actual_host && registered_suffix.as_bytes() == actual_suffix.as_bytes()
}
fn loopback_parts(raw: &str) -> Option<(&str, &str)> {
    let rest = raw.strip_prefix("http://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_end);
    if suffix.starts_with('#') {
        return None;
    }
    let (host, port) = if let Some(after) = authority.strip_prefix("[::1]") {
        ("[::1]", after)
    } else {
        let after = authority.strip_prefix("127.0.0.1")?;
        ("127.0.0.1", after)
    };
    if port.is_empty() {
        return Some((host, suffix));
    }
    let port = port.strip_prefix(':')?;
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || !port.parse::<u16>().is_ok_and(|port| port != 0)
    {
        return None;
    }
    Some((host, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_access_is_granted_only_by_server_consent() {
        let client = FirstPartyClient::new(
            "client",
            "Client",
            vec![RegisteredRedirect::new("com.example:/cb", RedirectKind::Exact).unwrap()],
            ["openid", "offline_access"],
            ["https://api.example/resource"],
            None,
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
        )
        .unwrap();
        let registry = ClientRegistry::new(vec![client]).unwrap();
        let pending = registry
            .validate_pending(AuthorizationRequest {
                client_id: "client",
                redirect_uri: "com.example:/cb",
                response_type: "code",
                code_challenge_method: "S256",
                code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                scopes: &["openid", "offline_access"],
                resource: Some("https://api.example/resource"),
            })
            .unwrap();
        assert!(matches!(
            pending.clone().approve(false),
            Err(OAuthError::ConsentRequired)
        ));
        assert!(pending.approve(true).unwrap().issue_refresh_token());
    }
}
